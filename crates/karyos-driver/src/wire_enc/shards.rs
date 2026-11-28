// SPDX-License-Identifier: Apache-2.0

//! Receive shards per encrypted endpoint (`quantstratum-docs:
//! karyos/adr/0127-encrypted-sharded-receive-per-endpoint.md`).
//!
//! An encrypted endpoint may run a fixed number of receive shard threads
//! ([`EncShardConfig::shards`]; 0, the default, is the role's own receive).
//! Each shard receives in batches from a duplicate of the endpoint's
//! socket into its own preallocated slab; the kernel hands each datagram
//! to exactly one of them, and while they run the role does not receive
//! from that socket (decision 1). This module is the set of one endpoint:
//!
//! - **Steps 1 to 4 on the shard** (decision 2), against the published
//!   `Snapshot`: the fixed fields, the epoch pair against the accepted
//!   set (the committed keys of the binding and its next epochs, or for a
//!   domain 5 SETUP the stream's held file epochs), the sequence cap, the
//!   open-rate charge on the channel's shared atomic counter, committed or
//!   scratch ([`super::OpenRate`], decision 3), the key age against the
//!   key's original deadline, a scratch derivation's its predecessor's
//!   (decision 4), and the key selection under a lease (ADR-0126 decision
//!   5): a committed key, or a scratch derivation into the lane slot's own
//!   preallocated key, erased after its open. Then the job goes to the
//!   shard's lane for a verifier. The replay precheck (step 5) is the
//!   role's re-check, after verification; the promotion of a next epoch
//!   stays the role's commit.
//! - **One lane per shard** (decision 5): a ring of job slots the shard
//!   fills in its receive order, verifiers run (the key age checked again
//!   just before the open), and the role consumes in that order. At most
//!   [`ENC_SHARD_IN_FLIGHT`] jobs, the replay window, are in flight across
//!   the lanes of a set.
//! - **One ring per shard for everything else** (decision 6): datagrams
//!   that are not encrypted for this endpoint's subscriptions (control,
//!   other classes, a local publication's envelopes), and those only the
//!   role can act on (an epoch ahead of the accepted set, which starts a
//!   resynchronisation; an unbound source naming a verified target, which
//!   causes a SOLICIT; a withdrawn or earlier-generation opener) go to the
//!   role whole, in a bounded ring; a full ring drops before work and
//!   counts it. The role serves its inputs round robin with a fixed budget
//!   per input (`serve_round`).
//! - **Withdrawal and shutdown** (decision 7): the role publishes the
//!   snapshot under a write lock, so once `ShardSet::publish` returns no
//!   shard dispatches under what it removed; `ShardSet::stop_shards`
//!   and the drop stop and join the shards before their descriptors
//!   close.
//!
//! Nothing a shard, a verifier or the role does per datagram allocates.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, RwLock};
use std::thread::{JoinHandle, Thread};
use std::time::{Duration, Instant};

use karyos_io::sockets::ops::{Errno, RecvResult, SharedRecv};
use karyos_protocol::network::Alias;
use karyos_protocol::protection::aes_gcm_siv::{
    AesGcmSiv, BOOTSTRAP_SEQ_CAP, Domain, EncRejection, HEADER_LEN, KeyContext, MAX_DATAGRAM,
    MAX_PLAINTEXT, PublicationIdentity, Salt,
};
use zeroize::Zeroizing;

use super::verify_pool::{Done, EncVerifyConfig, MAX_ENC_VERIFIERS, Outcome};
use super::{
    CHANNEL_FILES, ENC_REASONS, EncRejections, Header, KeyCell, KeyKind, Lease, OpenRate,
    OpenerShare, Ticket, erase_scratch, header, is_envelope, reason_index, scratch_slot,
    vm_generation,
};
use crate::wire_keys::KEY_LEN;

/// Receive shards an encrypted endpoint may run at most.
pub const MAX_ENC_SHARDS: u16 = 8;
/// Jobs in flight across the lanes of one endpoint's shards at most: the
/// replay window, so that an older datagram still in flight is never more
/// than the window behind the newest committed sequence of its context
/// (decision 5).
pub const ENC_SHARD_IN_FLIGHT: u32 = 1_024;
const _: () = assert!(ENC_SHARD_IN_FLIGHT as u64 == karyos_protocol::protection::replay::WINDOW);
/// Datagrams each shard's ring for the role holds by default.
pub const DEFAULT_ENC_SHARD_RING: u16 = 256;
/// Datagrams each shard's ring holds at most (8 KiB each).
pub const MAX_ENC_SHARD_RING: u16 = 4_096;
/// Datagrams one shard receive call reads at most (one `recvmmsg`).
const SHARD_BATCH: usize = 64;
/// Empty receives a shard makes before it parks briefly: an idle shard
/// gives its core back within a few microseconds.
const SHARD_IDLE_SPINS: u32 = 16;
/// Spin hints between two empty receives of a shard: an empty socket is
/// not polled back to back, which would take its queue's lock from the
/// senders and the other shards.
const SHARD_EMPTY_BACKOFF: u32 = 256;
/// How long an idle shard parks between receives.
const SHARD_IDLE_PARK: Duration = Duration::from_micros(20);
/// Spins an idle verifier makes before it parks.
const VERIFIER_IDLE_SPINS: u32 = 1 << 12;

/// The receive shards of an encrypted endpoint (ADR-0127): `shards`
/// threads, each with its own ring of `ring` datagrams for the role. The
/// verifier threads and lane slots are the endpoint's
/// [`EncVerifyConfig`]'s (at least one verifier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncShardConfig {
    /// Receive shard threads per encrypted endpoint, 0 to
    /// [`MAX_ENC_SHARDS`]; 0 receives on the role, as before.
    pub shards: u16,
    /// Datagrams each shard's ring for the role holds, 1 to
    /// [`MAX_ENC_SHARD_RING`].
    pub ring: u16,
}

impl Default for EncShardConfig {
    fn default() -> Self {
        Self {
            shards: 0,
            ring: DEFAULT_ENC_SHARD_RING,
        }
    }
}

impl EncShardConfig {
    /// Checks the bounds.
    ///
    /// # Errors
    ///
    /// The bound a value is outside of.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.shards > MAX_ENC_SHARDS {
            return Err("enc_shards.shards must be at most 8");
        }
        if !(1..=MAX_ENC_SHARD_RING).contains(&self.ring) {
            return Err("enc_shards.ring must be 1 to 4096");
        }
        Ok(())
    }
}

/// Rejections by reason that receive shards count for one channel, shared
/// with its role, which adds them to the channel's own.
#[derive(Debug)]
pub(crate) struct SharedRejections([AtomicU64; ENC_REASONS]);

impl Default for SharedRejections {
    fn default() -> Self {
        Self(core::array::from_fn(|_| AtomicU64::new(0)))
    }
}

impl SharedRejections {
    /// Counts one rejection for `reason`.
    pub(crate) fn bump(&self, reason: EncRejection) {
        if let Some(count) = self.0.get(reason_index(reason)) {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// `own` with these counts added.
    pub(crate) fn merged(&self, own: EncRejections) -> EncRejections {
        let mut merged = own;
        for (total, shared) in merged.counts.iter_mut().zip(self.0.iter()) {
            *total = total.saturating_add(shared.load(Ordering::Relaxed));
        }
        merged
    }
}

/// One committed key as a shard reads it: its epoch pair, the key, its
/// original age deadline, and the end of its overlap for a previous key
/// (`u64::MAX` for the current one).
pub(crate) struct KeyView {
    pub(crate) epochs: (u32, u16),
    pub(crate) key: Arc<KeyCell>,
    pub(crate) deadline: u64,
    pub(crate) until: u64,
}

/// The inputs of one next-epoch scratch derivation a shard may make
/// (decision 2, step 4): the context, the opener's current one at that
/// epoch pair, and the IKM of its file epoch, erased on drop.
pub(crate) struct ScratchView {
    pub(crate) context: KeyContext,
    pub(crate) ikm: Zeroizing<[u8; KEY_LEN]>,
}

/// One held channel file epoch of a stream and its IKM, erased on drop:
/// the epochs a domain 5 SETUP is accepted and derived under.
pub(crate) struct SetupView {
    pub(crate) epoch: u32,
    pub(crate) ikm: Zeroizing<[u8; KEY_LEN]>,
}

/// One opener as a shard reads it ([`super::EncOpener::shard_view`]): its
/// committed keys and the next epochs it accepts.
pub(crate) struct OpenerView {
    pub(crate) instance: u64,
    pub(crate) generation: u64,
    pub(crate) share: Arc<OpenerShare>,
    pub(crate) current: KeyView,
    pub(crate) previous: Option<KeyView>,
    pub(crate) next: [Option<ScratchView>; 2],
}

/// An encrypted subscription of the endpoint: its stream, its channel's
/// shared open-rate counters, the rejections its shards count, its held
/// file epochs for domain 5 derivations and the share its domain 5 jobs
/// are leased under (withdrawn with the subscription).
pub(crate) struct StreamView {
    pub(crate) stream_id: i32,
    pub(crate) rate: OpenRate,
    pub(crate) counts: Arc<SharedRejections>,
    pub(crate) setup: [Option<SetupView>; CHANNEL_FILES],
    pub(crate) setup_share: Arc<OpenerShare>,
}

/// A bound encrypted image: its role's tag, the alias and founding source
/// it is bound to, and its opener.
pub(crate) struct BindingView<B> {
    pub(crate) tag: B,
    pub(crate) alias: Alias,
    pub(crate) source: SocketAddr,
    pub(crate) opener: OpenerView,
}

/// What the role publishes for its shards: the withdrawal fence its jobs
/// carry, the key fence, the endpoint's encrypted streams, its local
/// encrypted publications (their envelopes go to the role), its bound
/// encrypted images (`complete` once every one fit), the targets a
/// verified SETUP named (the only unbound DATA the role solicits for,
/// H8-02) and the retired publication identities with the end of their
/// quarantine (dropped before any derivation, ADR-0114 section 7). Its
/// tables are reserved when the set is made and refilled within that
/// capacity, so a publication allocates nothing.
pub(crate) struct Snapshot<B> {
    pub(crate) fence: u64,
    /// The VM generation the role published it in: its jobs carry it, and
    /// a shard dispatches nothing once the process has moved past it.
    pub(crate) generation: u64,
    pub(crate) admits: Option<Arc<crate::wire_auth::KeyGeneration>>,
    pub(crate) streams: Vec<StreamView>,
    pub(crate) published: Vec<Alias>,
    pub(crate) bindings: Vec<BindingView<B>>,
    pub(crate) complete: bool,
    pub(crate) verified: Vec<(Alias, PublicationIdentity)>,
    pub(crate) retired: Vec<(PublicationIdentity, u64)>,
}

impl<B> Snapshot<B> {
    /// Empties it: no shard dispatches anything after this is published,
    /// and every IKM copy it held is erased.
    pub(crate) fn clear(&mut self) {
        self.streams.clear();
        self.published.clear();
        self.bindings.clear();
        self.complete = false;
        self.verified.clear();
        self.retired.clear();
    }
}

/// Which key a shard selected for a job (decision 2, step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JobKind {
    /// A committed key of a bound image, under its lease.
    Committed,
    /// The next epoch of a bound image: a scratch derivation, promoted
    /// only by the role's commit.
    Next,
    /// A domain 5 SETUP: a scratch derivation from its header.
    Setup,
}

/// The context a shard records for a job (ADR-0126 decision 2): the
/// binding's tag (none for a SETUP), the key it selected, the parsed
/// header, the source and alias it came from, the header's publication,
/// the withdrawal fence it was dispatched under and the [`Ticket`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct ShardJob<B> {
    pub(crate) tag: Option<B>,
    pub(crate) kind: JobKind,
    pub(crate) head: Header,
    pub(crate) source: SocketAddr,
    pub(crate) alias: Alias,
    pub(crate) publication: Option<PublicationIdentity>,
    pub(crate) fence: u64,
    pub(crate) ticket: Ticket,
}

/// Slot states, as the verifier pool's.
const FREE: u8 = 0;
const QUEUED: u8 = 1;
const RUNNING: u8 = 2;
const DONE: u8 = 3;

/// A value on cache lines of its own.
#[derive(Debug, Default)]
#[repr(align(128))]
struct Padded<T>(T);

/// The contents of one lane slot.
struct LaneJob<B> {
    bytes: [u8; MAX_DATAGRAM],
    len: usize,
    plain: [u8; MAX_PLAINTEXT],
    lease: Option<Lease>,
    outcome: Outcome,
    /// The key's original age deadline: the verifier refuses the job
    /// without an open once the clock is past it (decision 4).
    deadline: u64,
    context: Option<ShardJob<B>>,
    /// The slot's own key for a scratch derivation (step 4), made at rest
    /// with the lane and re-keyed in place, so the data path constructs no
    /// key; erased after the open, or when the job ends without one.
    scratch: AesGcmSiv,
    /// Whether `scratch` holds a derived key.
    derived: bool,
}

impl<B> LaneJob<B> {
    /// Erases the slot's scratch key once its job is done with it.
    fn forget(&mut self) {
        if self.derived {
            erase_scratch(&mut self.scratch);
            self.derived = false;
        }
    }
}

/// One lane slot.
#[repr(align(128))]
struct LaneCell<B> {
    state: AtomicU8,
    job: Mutex<LaneJob<B>>,
}

impl<B> LaneCell<B> {
    fn lock(&self) -> MutexGuard<'_, LaneJob<B>> {
        self.job.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One shard's lane: a ring of slots its shard fills in receive order
/// (`produced`), verifiers claim (`claimed`) and the role consumes in the
/// same order (`consumed`). A slot is refilled only after the role freed
/// it, so the order is the shard's.
struct Lane<B> {
    cells: Box<[LaneCell<B>]>,
    produced: Padded<AtomicU64>,
    claimed: Padded<AtomicU64>,
    consumed: Padded<AtomicU64>,
}

impl<B> Lane<B> {
    /// `slots` slots, each with its scratch key at rest; `None` if a key
    /// cannot be made.
    fn new(slots: usize) -> Option<Self> {
        let cells: Box<[LaneCell<B>]> = (0..slots)
            .map(|_| {
                Some(LaneCell {
                    state: AtomicU8::new(FREE),
                    job: Mutex::new(LaneJob {
                        bytes: [0; MAX_DATAGRAM],
                        len: 0,
                        plain: [0; MAX_PLAINTEXT],
                        lease: None,
                        outcome: Outcome::Cancelled,
                        deadline: 0,
                        context: None,
                        scratch: scratch_slot()?,
                        derived: false,
                    }),
                })
            })
            .collect::<Option<_>>()?;
        // A mutex that sets itself up on first use is set up now.
        for cell in &*cells {
            drop(cell.lock());
        }
        Some(Self {
            cells,
            produced: Padded::default(),
            claimed: Padded::default(),
            consumed: Padded::default(),
        })
    }

    fn cell(&self, at: u64) -> Option<&LaneCell<B>> {
        let size = u64::try_from(self.cells.len()).ok()?.max(1);
        self.cells.get(usize::try_from(at % size).ok()?)
    }

    /// Takes the next claim and runs its job; whether it ran one.
    fn run_one(&self, clock: &AtomicU64) -> bool {
        loop {
            let claimed = self.claimed.0.load(Ordering::Acquire);
            if claimed >= self.produced.0.load(Ordering::Acquire) {
                return false;
            }
            if self
                .claimed
                .0
                .compare_exchange_weak(
                    claimed,
                    claimed.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }
            if self.cell(claimed).is_some_and(|cell| run(cell, clock)) {
                return true;
            }
        }
    }
}

/// Runs the job in `cell` if it is queued: the withdrawn mark, then the
/// key age against the clock, then the open, under the slot's scratch key
/// for a scratch derivation, which is erased then. Whether it ran it.
fn run<B>(cell: &LaneCell<B>, clock: &AtomicU64) -> bool {
    if cell
        .state
        .compare_exchange(QUEUED, RUNNING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    let mut guard = cell.lock();
    let LaneJob {
        bytes,
        len,
        plain,
        lease,
        outcome,
        deadline,
        scratch,
        derived,
        ..
    } = &mut *guard;
    *outcome = match lease.as_ref() {
        Some(lease) if !lease.is_withdrawn() => {
            if clock.load(Ordering::Acquire) > *deadline {
                // Decision 4: queued work that crossed the key's age is
                // refused without an open.
                Outcome::Failed(EncRejection::KeyAge)
            } else {
                let datagram = bytes.get(..*len).unwrap_or_default();
                let key = if *derived {
                    Some(&*scratch)
                } else {
                    lease.key()
                };
                match key.map(|key| key.open_verified_into(datagram, plain)) {
                    Some(Ok(opened)) => Outcome::Verified(opened),
                    Some(Err(reason)) => Outcome::Failed(reason),
                    None => Outcome::Cancelled,
                }
            }
        }
        _ => Outcome::Cancelled,
    };
    guard.forget();
    drop(guard);
    cell.state.store(DONE, Ordering::Release);
    true
}

/// One datagram of a ring.
struct RingSlot {
    bytes: Box<[u8]>,
    len: usize,
    source: Option<SocketAddr>,
}

/// One shard's bounded ring of other traffic for the role: the shard
/// pushes at `tail`, the role pops at `head`.
struct Ring {
    slots: Box<[Mutex<RingSlot>]>,
    head: Padded<AtomicU64>,
    tail: Padded<AtomicU64>,
}

impl Ring {
    fn new(entries: usize, stride: usize) -> Self {
        let slots: Box<[Mutex<RingSlot>]> = (0..entries)
            .map(|_| {
                Mutex::new(RingSlot {
                    bytes: vec![0; stride].into_boxed_slice(),
                    len: 0,
                    source: None,
                })
            })
            .collect();
        for slot in &*slots {
            drop(slot.lock().unwrap_or_else(PoisonError::into_inner));
        }
        Self {
            slots,
            head: Padded::default(),
            tail: Padded::default(),
        }
    }

    fn slot(&self, at: u64) -> Option<MutexGuard<'_, RingSlot>> {
        let size = u64::try_from(self.slots.len()).ok()?.max(1);
        self.slots
            .get(usize::try_from(at % size).ok()?)
            .map(|slot| slot.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Copies `bytes` from `source` in; whether there was room.
    fn push(&self, bytes: &[u8], source: SocketAddr) -> bool {
        let tail = self.tail.0.load(Ordering::Relaxed);
        let size = u64::try_from(self.slots.len()).unwrap_or(0);
        if tail.saturating_sub(self.head.0.load(Ordering::Acquire)) >= size {
            return false;
        }
        let Some(mut slot) = self.slot(tail) else {
            return false;
        };
        let Some(target) = slot.bytes.get_mut(..bytes.len()) else {
            return false;
        };
        target.copy_from_slice(bytes);
        slot.len = bytes.len();
        slot.source = Some(source);
        drop(slot);
        self.tail.0.store(tail.wrapping_add(1), Ordering::Release);
        true
    }

    /// The oldest datagram, copied into `into`: its length and source.
    fn pop(&self, into: &mut [u8]) -> Option<(usize, SocketAddr)> {
        let head = self.head.0.load(Ordering::Relaxed);
        if head >= self.tail.0.load(Ordering::Acquire) {
            return None;
        }
        let taken = {
            let slot = self.slot(head)?;
            let len = slot.len;
            let copied = match (into.get_mut(..len), slot.bytes.get(..len)) {
                (Some(target), Some(source)) => {
                    target.copy_from_slice(source);
                    true
                }
                _ => false,
            };
            slot.source.filter(|_| copied).map(|source| (len, source))
        };
        self.head.0.store(head.wrapping_add(1), Ordering::Release);
        taken
    }
}

/// What one shard counts (no reason of a channel's).
#[derive(Debug, Default)]
#[repr(align(128))]
struct ShardCounts {
    /// Datagrams received.
    received: AtomicU64,
    /// Datagrams handed to the role through the ring.
    forwarded: AtomicU64,
    /// Datagrams a full ring dropped before any work (decision 6).
    ring_full: AtomicU64,
    /// Oversize datagrams and ones with no source, dropped as the role's
    /// receive drops them: taken by the role into its own counter.
    backend_drops: AtomicU64,
    /// Receive calls that failed with something other than an empty queue.
    errors: AtomicU64,
    /// Receive calls that found nothing (decision 7, the quiet wait).
    passes: AtomicU64,
    /// Scratch derivations dispatched (step 4: the next epoch, domain 5).
    scratch: AtomicU64,
}

/// What the shards, the verifiers and the role of one endpoint share.
struct SetShared<B> {
    snapshot: RwLock<Snapshot<B>>,
    lanes: Box<[Lane<B>]>,
    rings: Box<[Ring]>,
    counts: Box<[ShardCounts]>,
    /// Jobs in flight across the lanes, at most `cap`.
    in_flight: Padded<AtomicU32>,
    cap: u32,
    /// The role's clock, published every duty: what the shards and the
    /// verifiers check the rate intervals, overlaps and key ages against.
    clock: Padded<AtomicU64>,
    /// `max_datagram + 1`, a receive slot.
    stride: usize,
    max_datagram: usize,
    shards_stop: AtomicBool,
    verifiers_stop: AtomicBool,
    /// Per verifier: parked, waiting for a dispatch.
    sleeping: Box<[AtomicBool]>,
    verifier_threads: OnceLock<Box<[Option<Thread>]>>,
    /// The datagram length whose shard-handled datagrams are counted
    /// (tests: the R4 intake count).
    #[cfg(test)]
    watch: (core::sync::atomic::AtomicUsize, AtomicU64),
}

/// What a shard did with one datagram.
enum Step {
    /// To the role, through the ring.
    Forward,
    /// Dispatched to a verifier.
    Dispatched,
    /// Refused before the open and counted.
    Refused,
}

/// Whether the process is still in VM generation `generation`. The
/// generation is process wide; tests keep one per thread, the role's,
/// which the snapshot carries, so a shard thread there relies on the
/// role's take-back alone.
fn current(generation: u64) -> bool {
    #[cfg(not(test))]
    let current = generation == vm_generation::generation();
    #[cfg(test)]
    let current = {
        let _ = generation;
        true
    };
    current
}

/// The authenticated header bytes of `bytes`.
fn header_of(bytes: &[u8]) -> [u8; HEADER_LEN] {
    let mut head = [0_u8; HEADER_LEN];
    if let Some(source) = bytes.get(..HEADER_LEN) {
        head.copy_from_slice(source);
    }
    head
}

/// The alias of an envelope's header.
fn envelope_alias(bytes: &[u8]) -> Option<Alias> {
    let word = |at: usize| {
        bytes
            .get(at..at.checked_add(4)?)?
            .try_into()
            .ok()
            .map(i32::from_le_bytes)
    };
    Some(Alias {
        session_id: word(20)?,
        stream_id: word(24)?,
    })
}

impl<B> SetShared<B> {
    /// The tables of `count` shards: lanes of `slots` and rings of `ring`
    /// datagrams of up to `max_datagram` bytes, `verifiers` sleeping
    /// marks, and an empty snapshot with room for `streams` and
    /// `bindings`.
    fn new(
        count: usize,
        (slots, ring): (u16, u16),
        max_datagram: usize,
        verifiers: usize,
        (streams, bindings, parties): (usize, usize, usize),
    ) -> Option<Self> {
        let slots = usize::from(slots).clamp(1, ENC_SHARD_IN_FLIGHT as usize);
        let stride = max_datagram.saturating_add(1);
        Some(Self {
            snapshot: RwLock::new(Snapshot {
                fence: 0,
                generation: vm_generation::generation(),
                admits: None,
                streams: Vec::with_capacity(streams),
                published: Vec::with_capacity(streams),
                bindings: Vec::with_capacity(bindings),
                complete: false,
                verified: Vec::with_capacity(parties),
                retired: Vec::with_capacity(parties),
            }),
            lanes: (0..count)
                .map(|_| Lane::new(slots))
                .collect::<Option<_>>()?,
            rings: (0..count)
                .map(|_| Ring::new(usize::from(ring.max(1)), stride))
                .collect(),
            counts: (0..count).map(|_| ShardCounts::default()).collect(),
            in_flight: Padded(AtomicU32::new(0)),
            cap: ENC_SHARD_IN_FLIGHT,
            clock: Padded(AtomicU64::new(0)),
            stride,
            max_datagram,
            shards_stop: AtomicBool::new(false),
            verifiers_stop: AtomicBool::new(false),
            sleeping: (0..verifiers).map(|_| AtomicBool::new(false)).collect(),
            verifier_threads: OnceLock::new(),
            #[cfg(test)]
            watch: (core::sync::atomic::AtomicUsize::new(0), AtomicU64::new(0)),
        })
    }
}

/// The key a shard selected for a domain 1 datagram (step 4).
enum Pick<'a> {
    Committed(&'a KeyView),
    Next(&'a ScratchView),
}

/// The inputs of a scratch derivation into a lane slot, and the refusal
/// a derivation that does not take gives.
struct Derivation<'a> {
    context: KeyContext,
    ikm: &'a [u8; KEY_LEN],
    refusal: EncRejection,
}

impl<B: Copy> SetShared<B> {
    /// Steps 1 to 4 for one datagram from `source`, then the dispatch to
    /// shard `me`'s lane (decision 2).
    fn take(
        &self,
        me: usize,
        snapshot: &Snapshot<B>,
        bytes: &[u8],
        source: SocketAddr,
        now: u64,
    ) -> Step {
        if !is_envelope(bytes) || vm_generation::quiesced() || !current(snapshot.generation) {
            return Step::Forward;
        }
        let Some(alias) = envelope_alias(bytes) else {
            return Step::Forward;
        };
        if snapshot.published.contains(&alias)
            || snapshot
                .admits
                .as_ref()
                .is_some_and(|keys| !keys.admits_now(crate::wire_auth::Side::Receiver))
        {
            return Step::Forward;
        }
        let Some(stream) = snapshot
            .streams
            .iter()
            .find(|stream| stream.stream_id == alias.stream_id)
        else {
            return Step::Forward;
        };
        // Step 1.
        let head = match header(bytes) {
            Ok(head) => head,
            Err(reason) => {
                stream.counts.bump(reason);
                return Step::Refused;
            }
        };
        // ADR-0114 section 7: a retired full identity inside its
        // quarantine selects a key the receiver no longer holds; dropped
        // before any derivation.
        if head.publication.is_some_and(|publication| {
            snapshot
                .retired
                .iter()
                .any(|(retired, until)| *retired == publication && now < *until)
        }) {
            stream.counts.bump(EncRejection::RetiredParty);
            return Step::Refused;
        }
        match head.domain {
            Domain::Sender => {
                self.take_data(me, snapshot, stream, bytes, (source, alias, &head), now)
            }
            Domain::Setup => {
                self.take_setup(me, snapshot, stream, bytes, (source, alias, &head), now)
            }
            _ => {
                stream.counts.bump(EncRejection::Domain);
                Step::Refused
            }
        }
    }

    /// Steps 2 to 4 for a domain 1 datagram of `stream`, then its dispatch.
    fn take_data(
        &self,
        me: usize,
        snapshot: &Snapshot<B>,
        stream: &StreamView,
        bytes: &[u8],
        (source, alias, head): (SocketAddr, Alias, &Header),
        now: u64,
    ) -> Step {
        let Some(binding) = snapshot
            .bindings
            .iter()
            .find(|binding| binding.alias == alias && binding.source == source)
        else {
            // No key for an unbound source. The role acts only on DATA
            // naming a target a verified SETUP named for this alias (its
            // SOLICIT, H8-02); a snapshot that could not hold every
            // binding hands it over too. Anything else is refused here.
            let solicits = head
                .publication
                .is_some_and(|publication| snapshot.verified.contains(&(alias, publication)));
            if solicits || !snapshot.complete {
                return Step::Forward;
            }
            stream.counts.bump(EncRejection::Binding);
            return Step::Refused;
        };
        let view = &binding.opener;
        if view.share.withdrawn.load(Ordering::Acquire) || view.generation != snapshot.generation {
            return Step::Forward;
        }
        // Step 2: the accepted set of the snapshot, the committed keys and
        // the next epochs. An epoch ahead of it starts a
        // resynchronisation, the role's decision; one behind is refused.
        let pair = (head.key_epoch, head.party_epoch);
        let pick = if pair == view.current.epochs {
            Pick::Committed(&view.current)
        } else if let Some(previous) = view
            .previous
            .as_ref()
            .filter(|previous| previous.epochs == pair && now < previous.until)
        {
            Pick::Committed(previous)
        } else if let Some(next) = view
            .next
            .iter()
            .flatten()
            .find(|next| (next.context.key_epoch, next.context.party_epoch) == pair)
        {
            Pick::Next(next)
        } else if pair > view.current.epochs {
            return Step::Forward;
        } else {
            stream.counts.bump(EncRejection::Epoch);
            return Step::Refused;
        };
        // Step 3, then 3a: a scratch derivation is charged to the scratch
        // budget and carries its predecessor's deadline (decision 4).
        let (kind, deadline) = match pick {
            Pick::Committed(key) => (KeyKind::Committed, key.deadline),
            Pick::Next(_) => (KeyKind::Scratch, view.current.deadline),
        };
        let refused = if head.seq >= head.domain.seq_cap() {
            Some(EncRejection::SequenceCap)
        } else if let Err(reason) = stream.rate.charge(kind, now) {
            Some(reason)
        } else if now > deadline {
            Some(EncRejection::KeyAge)
        } else {
            None
        };
        if let Some(reason) = refused {
            stream.counts.bump(reason);
            return Step::Refused;
        }
        // Step 4: the committed key under a lease, its fields checked now;
        // or the next epoch's scratch derivation, under a lease on the
        // opener, derived into the lane slot at dispatch.
        let (lease, derivation, seq, kind) = match pick {
            Pick::Committed(key) => {
                let seq = match key.key.check_fields(bytes) {
                    Ok(seq) => seq,
                    Err(reason) => {
                        stream.counts.bump(reason);
                        return Step::Refused;
                    }
                };
                let lease = Lease::take(&view.share, Some(Arc::clone(&key.key)));
                (lease, None, seq, JobKind::Committed)
            }
            Pick::Next(next) => {
                let derivation = Derivation {
                    context: next.context,
                    ikm: &next.ikm,
                    refusal: EncRejection::Epoch,
                };
                (
                    Lease::take(&view.share, None),
                    Some(derivation),
                    0,
                    JobKind::Next,
                )
            }
        };
        let job = ShardJob {
            tag: Some(binding.tag),
            kind,
            head: *head,
            source,
            alias,
            publication: head.publication,
            fence: snapshot.fence,
            ticket: Ticket {
                opener: view.instance,
                epochs: pair,
                seq,
                generation: view.generation,
                len: bytes.len(),
                header: header_of(bytes),
            },
        };
        self.finish(me, stream, bytes, (lease, deadline, job), derivation)
    }

    /// Steps 2 to 4 for a domain 5 SETUP of `stream` (as
    /// [`super::open_bootstrap_in`] before its open), then its dispatch:
    /// a held file epoch at `party_epoch` 0, the bootstrap sequence cap,
    /// the scratch charge, a named publication, and the scratch
    /// derivation from the header under a lease on the stream.
    fn take_setup(
        &self,
        me: usize,
        snapshot: &Snapshot<B>,
        stream: &StreamView,
        bytes: &[u8],
        (source, alias, head): (SocketAddr, Alias, &Header),
        now: u64,
    ) -> Step {
        let setup = stream
            .setup
            .iter()
            .flatten()
            .find(|setup| head.party_epoch == 0 && setup.epoch == head.key_epoch);
        let refused = match (setup, head.publication) {
            (None, _) => Some(EncRejection::Epoch),
            _ if head.seq >= BOOTSTRAP_SEQ_CAP => Some(EncRejection::SequenceCap),
            _ if stream.rate.charge(KeyKind::Scratch, now).is_err() => Some(EncRejection::OpenRate),
            (_, None) => Some(EncRejection::Party),
            (Some(_), Some(_)) => None,
        };
        let (Some(setup), Some(publication), None) = (setup, head.publication, refused) else {
            stream.counts.bump(refused.unwrap_or(EncRejection::Party));
            return Step::Refused;
        };
        let derivation = Derivation {
            context: KeyContext {
                domain: Domain::Setup,
                key_epoch: head.key_epoch,
                party_epoch: 0,
                session_id: head.session_id,
                stream_id: head.stream_id,
                publication,
                receiver: head.receiver,
                salt: Salt::Empty,
            },
            ikm: &setup.ikm,
            refusal: EncRejection::Party,
        };
        let job = ShardJob {
            tag: None,
            kind: JobKind::Setup,
            head: *head,
            source,
            alias,
            publication: head.publication,
            fence: snapshot.fence,
            ticket: Ticket {
                opener: 0,
                epochs: (head.key_epoch, 0),
                seq: 0,
                generation: snapshot.generation,
                len: bytes.len(),
                header: header_of(bytes),
            },
        };
        let lease = Lease::take(&stream.setup_share, None);
        self.finish(me, stream, bytes, (lease, u64::MAX, job), Some(derivation))
    }

    /// Dispatches a job whose checks passed; a refused dispatch is counted
    /// on `stream`, and its lease returns.
    fn finish(
        &self,
        me: usize,
        stream: &StreamView,
        bytes: &[u8],
        (lease, deadline, job): (Lease, u64, ShardJob<B>),
        derivation: Option<Derivation<'_>>,
    ) -> Step {
        let scratch = derivation.is_some();
        match self.dispatch(me, bytes, (lease, deadline, job), derivation) {
            Ok(()) => {
                if scratch && let Some(counts) = self.counts.get(me) {
                    counts.scratch.fetch_add(1, Ordering::Relaxed);
                }
                Step::Dispatched
            }
            Err(reason) => {
                stream.counts.bump(reason);
                Step::Refused
            }
        }
    }

    /// Queues `bytes` in lane `me` under `lease`, within the in-flight cap
    /// of the set; with a `derivation`, its scratch key is derived into the
    /// slot's own key first and the fields checked against it (step 4),
    /// which gives the job's sequence. A refused dispatch drops the lease,
    /// which returns, and leaves no derived key behind: the refusal.
    fn dispatch(
        &self,
        me: usize,
        bytes: &[u8],
        (lease, deadline, mut job): (Lease, u64, ShardJob<B>),
        derivation: Option<Derivation<'_>>,
    ) -> Result<(), EncRejection> {
        let busy = Err(EncRejection::VerifyBusy);
        let Some(lane) = self.lanes.get(me) else {
            return busy;
        };
        if bytes.len() > MAX_DATAGRAM {
            return busy;
        }
        if self.in_flight.0.fetch_add(1, Ordering::AcqRel) >= self.cap {
            self.in_flight.0.fetch_sub(1, Ordering::AcqRel);
            return busy;
        }
        let produced = lane.produced.0.load(Ordering::Relaxed);
        let Some(cell) = lane
            .cell(produced)
            .filter(|cell| cell.state.load(Ordering::Acquire) == FREE)
        else {
            self.in_flight.0.fetch_sub(1, Ordering::AcqRel);
            return busy;
        };
        {
            let mut held = cell.lock();
            if let Some(Derivation {
                context,
                ikm,
                refusal,
            }) = derivation
            {
                let job_held = &mut *held;
                let derived = match job_held.scratch.rekey(ikm, context, &[]) {
                    Ok(()) => {
                        job_held.derived = true;
                        job_held.scratch.check_fields(bytes)
                    }
                    Err(_) => Err(refusal),
                };
                match derived {
                    Ok(seq) => job.ticket.seq = seq,
                    Err(reason) => {
                        job_held.forget();
                        drop(held);
                        self.in_flight.0.fetch_sub(1, Ordering::AcqRel);
                        return Err(reason);
                    }
                }
            }
            if let Some(target) = held.bytes.get_mut(..bytes.len()) {
                target.copy_from_slice(bytes);
            }
            held.len = bytes.len();
            held.lease = Some(lease);
            held.outcome = Outcome::Cancelled;
            held.deadline = deadline;
            held.context = Some(job);
        }
        cell.state.store(QUEUED, Ordering::Release);
        lane.produced
            .0
            .store(produced.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// One receive batch of shard `me`: each datagram taken, dispatched or
    /// forwarded, under one read of the snapshot. Returns the datagrams.
    fn batch(&self, me: usize, slab: &[u8], results: &[RecvResult]) -> usize {
        let Some(counts) = self.counts.get(me) else {
            return 0;
        };
        let snapshot = self.snapshot.read().unwrap_or_else(PoisonError::into_inner);
        let now = self.clock.0.load(Ordering::Acquire);
        let (mut datagrams, mut dispatched) = (0_usize, false);
        for (at, result) in results.iter().enumerate() {
            let (len, truncated, source) = match *result {
                RecvResult::Datagram {
                    len,
                    truncated,
                    source,
                } => (len, truncated, source),
                RecvResult::Error(errno) => {
                    if errno != Errno::AGAIN && errno != Errno::INTR && errno != Errno::CONNREFUSED
                    {
                        counts.errors.fetch_add(1, Ordering::Relaxed);
                    }
                    continue;
                }
            };
            datagrams = datagrams.saturating_add(1);
            counts.received.fetch_add(1, Ordering::Relaxed);
            let bytes = at
                .checked_mul(self.stride)
                .and_then(|start| slab.get(start..)?.get(..len));
            let (Some(source), None, Some(bytes)) = (source, truncated, bytes) else {
                counts.backend_drops.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            if len > self.max_datagram {
                counts.backend_drops.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            match self.take(me, &snapshot, bytes, source, now) {
                Step::Forward => {
                    counts.forwarded.fetch_add(1, Ordering::Relaxed);
                    if !self
                        .rings
                        .get(me)
                        .is_some_and(|ring| ring.push(bytes, source))
                    {
                        counts.ring_full.fetch_add(1, Ordering::Relaxed);
                    }
                    continue;
                }
                Step::Dispatched => dispatched = true,
                Step::Refused => {}
            }
            #[cfg(test)]
            if len == self.watch.0.load(Ordering::Relaxed) {
                self.watch.1.fetch_add(1, Ordering::Relaxed);
            }
        }
        drop(snapshot);
        if dispatched {
            self.wake();
        }
        datagrams
    }

    /// Wakes one parked verifier, if any.
    fn wake(&self) {
        let Some(threads) = self.verifier_threads.get() else {
            return;
        };
        for (sleeping, thread) in self.sleeping.iter().zip(threads.iter()) {
            if let Some(thread) = thread
                && sleeping.load(Ordering::Acquire)
                && sleeping.swap(false, Ordering::SeqCst)
            {
                thread.unpark();
                return;
            }
        }
    }

    /// Whether a lane has a job no verifier claimed.
    fn waiting(&self) -> bool {
        self.lanes.iter().any(|lane| {
            lane.claimed.0.load(Ordering::SeqCst) < lane.produced.0.load(Ordering::SeqCst)
        })
    }

    /// Runs one queued job of any lane, from lane `from` on.
    fn run_any(&self, from: usize) -> bool {
        let lanes = self.lanes.len().max(1);
        (0..lanes).any(|offset| {
            self.lanes
                .get((from.saturating_add(offset)) % lanes)
                .is_some_and(|lane| lane.run_one(&self.clock.0))
        })
    }
}

/// One receive shard: batched receives from its own descriptor until
/// stopped; an idle one spins, then parks briefly.
fn shard<B: Copy>(shared: &SetShared<B>, me: usize, socket: &mut dyn SharedRecv, slab: &mut [u8]) {
    let mut results = [RecvResult::Error(Errno::AGAIN); SHARD_BATCH];
    let mut idle = 0_u32;
    while !shared.shards_stop.load(Ordering::Acquire) {
        let filled = socket
            .recv_batch(slab, shared.stride, &mut results)
            .min(SHARD_BATCH);
        let datagrams = shared.batch(me, slab, results.get(..filled).unwrap_or_default());
        if datagrams > 0 {
            idle = 0;
            continue;
        }
        if let Some(counts) = shared.counts.get(me) {
            counts.passes.fetch_add(1, Ordering::Release);
        }
        if idle < SHARD_IDLE_SPINS {
            idle = idle.saturating_add(1);
            for _ in 0..SHARD_EMPTY_BACKOFF {
                core::hint::spin_loop();
            }
        } else {
            std::thread::park_timeout(SHARD_IDLE_PARK);
        }
    }
}

/// One verifier of a set: runs the lanes' jobs, spins a little when idle,
/// then parks until a shard dispatches or the set stops.
fn verifier<B: Copy>(shared: &SetShared<B>, me: usize) {
    let mut idle = 0_u32;
    while !shared.verifiers_stop.load(Ordering::Acquire) {
        if shared.run_any(me) {
            idle = 0;
            continue;
        }
        if idle < VERIFIER_IDLE_SPINS {
            idle = idle.saturating_add(1);
            core::hint::spin_loop();
            continue;
        }
        idle = 0;
        let Some(sleeping) = shared.sleeping.get(me) else {
            std::thread::yield_now();
            continue;
        };
        sleeping.store(true, Ordering::SeqCst);
        if shared.waiting() || shared.verifiers_stop.load(Ordering::SeqCst) {
            sleeping.store(false, Ordering::SeqCst);
            continue;
        }
        std::thread::park();
        sleeping.store(false, Ordering::SeqCst);
    }
}

/// What a set's shards counted, summed over its shards.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShardStats {
    /// Receive shard threads running.
    pub shards: usize,
    /// Verifier threads running.
    pub verifiers: usize,
    /// Datagrams the shards received.
    pub received: u64,
    /// Datagrams handed to the role through the rings.
    pub forwarded: u64,
    /// Datagrams a full ring dropped before any work.
    pub ring_full: u64,
    /// Receive calls that failed.
    pub errors: u64,
    /// Scratch derivations the shards dispatched (the next epoch, domain
    /// 5).
    pub scratch: u64,
}

/// The receive shards of one encrypted endpoint, their lanes, rings and
/// verifiers (ADR-0127). Owned by the role; dropping it stops and joins
/// the shards, then the verifiers, after which every lease still in a
/// lane returns.
pub(crate) struct ShardSet<B> {
    shared: Arc<SetShared<B>>,
    shards: Vec<(Thread, JoinHandle<()>)>,
    verifiers: Vec<JoinHandle<()>>,
}

impl<B> core::fmt::Debug for ShardSet<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShardSet")
            .field("shards", &self.shards.len())
            .field("verifiers", &self.verifiers.len())
            .finish_non_exhaustive()
    }
}

impl<B: Copy + Send + Sync + 'static> ShardSet<B> {
    /// The set of `receivers.len()` shards (each a duplicate of the
    /// endpoint's socket), each with a lane of `verify.slots` and a ring of
    /// `config.ring` datagrams of up to `max_datagram` bytes, and
    /// `verify.verifiers` verifiers (at least one). Its snapshot is empty,
    /// with room for `tables`: streams and aliases, bound images, and
    /// verified targets and retired identities each: every datagram goes
    /// to the role until the role publishes.
    /// Control path: allocates the tables and starts the threads.
    ///
    /// `None` when no shard could start: the role keeps receiving itself.
    pub(crate) fn new(
        config: EncShardConfig,
        verify: EncVerifyConfig,
        receivers: Vec<Box<dyn SharedRecv>>,
        max_datagram: usize,
        tables: (usize, usize, usize),
    ) -> Option<Self> {
        let count = receivers.len();
        let verifiers = usize::from(verify.verifiers.clamp(1, MAX_ENC_VERIFIERS));
        let stride = max_datagram.saturating_add(1);
        let mut set = Self {
            shared: Arc::new(SetShared::new(
                count,
                (verify.slots, config.ring),
                max_datagram,
                verifiers,
                tables,
            )?),
            shards: Vec::with_capacity(count),
            verifiers: Vec::with_capacity(verifiers),
        };
        let mut threads = Vec::with_capacity(verifiers);
        for me in 0..verifiers {
            let held = Arc::clone(&set.shared);
            let started = std::thread::Builder::new()
                .name(format!("karyos-enc-shard-verify-{me}"))
                .spawn(move || verifier(&held, me));
            threads.push(started.as_ref().ok().map(|handle| handle.thread().clone()));
            if let Ok(handle) = started {
                set.verifiers.push(handle);
            }
        }
        let _ = set.shared.verifier_threads.set(threads.into_boxed_slice());
        for (me, mut socket) in receivers.into_iter().enumerate() {
            let held = Arc::clone(&set.shared);
            let mut slab = vec![0_u8; stride.saturating_mul(SHARD_BATCH)].into_boxed_slice();
            let started = std::thread::Builder::new()
                .name(format!("karyos-enc-shard-{me}"))
                .spawn(move || shard(&held, me, &mut *socket, &mut slab));
            if let Ok(handle) = started {
                set.shards.push((handle.thread().clone(), handle));
            }
        }
        (!set.shards.is_empty()).then_some(set)
    }

    /// Replaces the snapshot with what `fill` writes into it, under the
    /// write lock: once this returns no shard dispatches under anything
    /// `fill` removed (decision 7). `fill` must stay within the reserved
    /// capacity.
    pub(crate) fn publish(&self, fill: impl FnOnce(&mut Snapshot<B>)) {
        let mut snapshot = self
            .shared
            .snapshot
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        fill(&mut snapshot);
    }

    /// Publishes the role's clock for the shards and verifiers.
    pub(crate) fn set_clock(&self, now: u64) {
        self.shared.clock.0.store(now, Ordering::Release);
    }

    /// Shards running (tests).
    #[cfg(test)]
    pub(crate) fn shards(&self) -> usize {
        self.shards.len()
    }

    /// Lanes (and rings): one per shard asked for.
    pub(crate) fn lanes(&self) -> usize {
        self.shared.lanes.len()
    }

    /// Verifier threads running (tests).
    #[cfg(test)]
    pub(crate) fn verifiers(&self) -> usize {
        self.verifiers.len()
    }

    /// Jobs dispatched and not yet consumed, across the lanes (tests).
    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> usize {
        usize::try_from(self.shared.in_flight.0.load(Ordering::Acquire)).unwrap_or(usize::MAX)
    }

    /// Jobs lane `lane` has dispatched so far: the bound a settle waits up
    /// to.
    pub(crate) fn produced(&self, lane: usize) -> u64 {
        self.shared
            .lanes
            .get(lane)
            .map_or(0, |lane| lane.produced.0.load(Ordering::Acquire))
    }

    /// The oldest job of lane `lane`, if it is done: consumed and its slot
    /// freed, its plaintext copied to `plain` when it verified. `None`
    /// while it is not done (it holds back the lane's later ones) or the
    /// lane is empty. Allocates nothing.
    pub(crate) fn take(
        &self,
        lane: usize,
        plain: &mut [u8; MAX_PLAINTEXT],
    ) -> Option<Done<ShardJob<B>>> {
        let held = self.shared.lanes.get(lane)?;
        let consumed = held.consumed.0.load(Ordering::Relaxed);
        if consumed >= held.produced.0.load(Ordering::Acquire) {
            return None;
        }
        let cell = held.cell(consumed)?;
        if cell.state.load(Ordering::Acquire) != DONE {
            return None;
        }
        let done = {
            let mut job = cell.lock();
            let outcome = job.outcome;
            if let Outcome::Verified(opened) = outcome {
                let end = opened.frames.min(MAX_PLAINTEXT);
                if let (Some(target), Some(source)) = (plain.get_mut(..end), job.plain.get(..end)) {
                    target.copy_from_slice(source);
                }
            }
            let mut header = [0_u8; HEADER_LEN];
            if let Some(source) = job.bytes.get(..HEADER_LEN) {
                header.copy_from_slice(source);
            }
            let len = job.len;
            job.forget();
            job.context.take().map(|context| Done {
                context,
                outcome,
                lease: job.lease.take(),
                header,
                len,
            })
        };
        cell.state.store(FREE, Ordering::Release);
        held.consumed
            .0
            .store(consumed.wrapping_add(1), Ordering::Release);
        self.shared.in_flight.0.fetch_sub(1, Ordering::AcqRel);
        done
    }

    /// [`Self::take`], waiting for lane `lane`'s oldest job while the lane
    /// has consumed fewer than `limit` jobs; while it waits the role runs
    /// queued jobs itself, so it never waits on a verifier that is not
    /// running. `None` once `limit` jobs are consumed.
    pub(crate) fn take_waiting(
        &self,
        lane: usize,
        limit: u64,
        plain: &mut [u8; MAX_PLAINTEXT],
    ) -> Option<Done<ShardJob<B>>> {
        let held = self.shared.lanes.get(lane)?;
        loop {
            let consumed = held.consumed.0.load(Ordering::Acquire);
            if consumed >= limit || consumed >= held.produced.0.load(Ordering::Acquire) {
                return None;
            }
            if let Some(done) = self.take(lane, plain) {
                return Some(done);
            }
            if !held.run_one(&self.shared.clock.0) {
                core::hint::spin_loop();
            }
        }
    }

    /// The oldest datagram of shard `lane`'s ring, copied into `into`: its
    /// length and source.
    pub(crate) fn pop_other(&self, lane: usize, into: &mut [u8]) -> Option<(usize, SocketAddr)> {
        self.shared.rings.get(lane)?.pop(into)
    }

    /// The shards' backend drops since the last call, taken.
    pub(crate) fn take_backend_drops(&self) -> u64 {
        self.shared
            .counts
            .iter()
            .map(|counts| counts.backend_drops.swap(0, Ordering::AcqRel))
            .sum()
    }

    /// Cancels every queued job of every lane (ADR-0126 decision 5): no
    /// verifier starts it, and it ends cancelled; a running one finishes.
    /// Returns the jobs cancelled. Allocates nothing.
    pub(crate) fn cancel_all(&self) -> usize {
        let mut cancelled = 0_usize;
        for lane in &*self.shared.lanes {
            let (from, to) = (
                lane.consumed.0.load(Ordering::Acquire),
                lane.produced.0.load(Ordering::Acquire),
            );
            for at in from..to {
                let Some(cell) = lane.cell(at) else {
                    continue;
                };
                if cell
                    .state
                    .compare_exchange(QUEUED, RUNNING, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    let mut job = cell.lock();
                    job.outcome = Outcome::Cancelled;
                    job.forget();
                    drop(job);
                    cell.state.store(DONE, Ordering::Release);
                    cancelled = cancelled.saturating_add(1);
                }
            }
        }
        cancelled
    }

    /// Waits, at most `timeout`, until every shard has found its socket
    /// empty on a receive that started after this call: what was sent
    /// before it is then in a lane or a ring. Returns early, false, as soon
    /// as a shard receives anything meanwhile: traffic is flowing, and the
    /// next poll serves it. Whether every shard found its socket empty.
    pub(crate) fn quiet(&self, timeout: Duration) -> bool {
        let read = |field: fn(&ShardCounts) -> &AtomicU64| -> [u64; MAX_ENC_SHARDS as usize] {
            core::array::from_fn(|at| {
                self.shared
                    .counts
                    .get(at)
                    .map_or(0, |counts| field(counts).load(Ordering::Acquire))
            })
        };
        let marks = read(|counts| &counts.passes);
        let received = read(|counts| &counts.received);
        for (thread, _) in &self.shards {
            thread.unpark();
        }
        let start = Instant::now();
        loop {
            let quiet = self
                .shared
                .counts
                .iter()
                .zip(marks.iter())
                .take(self.shards.len())
                .all(|(counts, mark)| {
                    counts.passes.load(Ordering::Acquire) >= mark.saturating_add(2)
                });
            if quiet {
                return true;
            }
            if read(|counts| &counts.received) != received || start.elapsed() >= timeout {
                return false;
            }
            std::thread::yield_now();
        }
    }

    /// Stops and joins the shards (decision 7): once this returns nothing
    /// more is received or dispatched and their descriptors are closed;
    /// what they left in the lanes and rings stays for the role.
    pub(crate) fn stop_shards(&mut self) {
        self.shared.shards_stop.store(true, Ordering::SeqCst);
        for (thread, _) in &self.shards {
            thread.unpark();
        }
        for (_, handle) in self.shards.drain(..) {
            let _ = handle.join();
        }
    }

    /// What its shards counted (tests).
    #[cfg(test)]
    pub(crate) fn stats(&self) -> ShardStats {
        let sum = |field: fn(&ShardCounts) -> &AtomicU64| {
            self.shared
                .counts
                .iter()
                .map(|counts| field(counts).load(Ordering::Relaxed))
                .sum()
        };
        ShardStats {
            shards: self.shards.len(),
            verifiers: self.verifiers.len(),
            received: sum(|counts| &counts.received),
            forwarded: sum(|counts| &counts.forwarded),
            ring_full: sum(|counts| &counts.ring_full),
            errors: sum(|counts| &counts.errors),
            scratch: sum(|counts| &counts.scratch),
        }
    }

    /// Runs one queued job of any lane on this thread, as a verifier
    /// would (tests).
    #[cfg(test)]
    pub(crate) fn verify_one(&self) -> bool {
        self.shared.run_any(0)
    }

    /// Counts the shard-handled datagrams of `length` from now on (tests).
    #[cfg(test)]
    pub(crate) fn watch_length(&self, length: usize) {
        self.shared.watch.0.store(length, Ordering::Relaxed);
        self.shared.watch.1.store(0, Ordering::Relaxed);
    }

    /// The shard-handled datagrams of the watched length (tests).
    #[cfg(test)]
    pub(crate) fn watched(&self) -> u64 {
        self.shared.watch.1.load(Ordering::Relaxed)
    }
}

impl<B> Drop for ShardSet<B> {
    /// Stops and joins the shards, then the verifiers; the lanes, and
    /// every lease still in one, go with the last reference to them.
    fn drop(&mut self) {
        self.shared.shards_stop.store(true, Ordering::SeqCst);
        for (thread, _) in &self.shards {
            thread.unpark();
        }
        for (_, handle) in self.shards.drain(..) {
            let _ = handle.join();
        }
        self.shared.verifiers_stop.store(true, Ordering::SeqCst);
        if let Some(threads) = self.shared.verifier_threads.get() {
            for thread in threads.iter().flatten() {
                thread.unpark();
            }
        }
        for handle in self.verifiers.drain(..) {
            let _ = handle.join();
        }
    }
}

/// One poll of the role's inputs, round robin (decision 6): input `0` to
/// `inputs - 1` in turn, each served until `serve` finds nothing or
/// `budget` items, so a busy input never starves another. Returns the
/// items served.
pub(crate) fn serve_round(inputs: usize, budget: u32, mut serve: impl FnMut(usize) -> bool) -> u32 {
    let mut served = 0_u32;
    for input in 0..inputs {
        for _ in 0..budget {
            if !serve(input) {
                break;
            }
            served = served.saturating_add(1);
        }
    }
    served
}

#[cfg(test)]
mod tests;
