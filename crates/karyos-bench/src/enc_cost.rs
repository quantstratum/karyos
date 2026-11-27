// SPDX-License-Identifier: Apache-2.0

//! Send and receive cost of the encrypted profile ([`AesGcmSiv`], ADR-0114
//! "To verify": the complete send and receive cost under the frozen
//! manifest), measured as the authenticated profile's cost was
//! (`quantstratum-docs: karyos/evaluations/wire-auth-profile-v1`, E-7):
//! one complete `seal` or `open` of the envelope per sample, timed with
//! [`Instant`], beside the same loop over [`Trusted`] so that the added
//! cost is a difference of the two profiles' quantiles.
//!
//! - Send: the committed frames at the start of the datagram buffer to
//!   the sealed datagram ([`AesGcmSiv::seal_next`]).
//! - Receive: the received datagram to the verify and replay decision
//!   ([`AesGcmSiv::open_in_place`], then [`AesGcmSiv::mark`]).
//! - Both: the sum of one envelope's send and receive samples.
//!
//! Every sample is one envelope operation (one datagram), not one message:
//! a W5 envelope carries 20 messages, and `rekey` is one epoch change. A
//! rate derived from these rows (`1e9 / mean_ns`) is envelope operations
//! per second; messages per second multiply it by the point's messages
//! per envelope.
//!
//! Refilling the frames and copying the datagram to the receive buffer
//! precede each timed call and are outside every sample.

use std::hint::black_box;
use std::time::Instant;

use karyos_protocol::protection::aes_gcm_siv::{
    Domain, ENVELOPE_LEN, KeyContext, MAX_DATAGRAM, PairwiseKey, PublicationIdentity,
    ReceiverIdentity, Salt, TRAILER_LEN,
};
use karyos_protocol::protection::{AesGcmSiv, Protection, Trusted, Verdict};

use crate::manifest::{ALIGNMENT, HEADER, MtuRule, Shape};
use crate::workloads::BenchError;

/// The DATA envelope `E` of the encrypted profile (domain 1): the 68-byte
/// header and the 16-byte tag.
pub const E: u32 = 84;

/// The inner bytes of the control point: the largest control of
/// `network-control-schemas.md` 4.9, as in the authenticated evaluation.
pub const CONTROL_BYTES: usize = 152;

/// A measured point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Point {
    /// A DATA shape (W1 to W5) in domain 1, sized at `E_max` = [`E`] with
    /// `mtu` counting the envelope.
    Data(Shape),
    /// A [`CONTROL_BYTES`] receiver control in domain 4, with the pairwise
    /// trailer (an SM of F1 or F2).
    Control,
    /// One in-band epoch change of a domain 1 key ([`AesGcmSiv::rekey`]),
    /// the step of R5.
    Rekey,
}

impl Point {
    /// The point `name` names: `W1` to `W5`, `ctl152` or `rekey`.
    ///
    /// # Errors
    ///
    /// Any other name.
    pub fn of(name: &str) -> Result<Self, BenchError> {
        Ok(match name {
            "W1" => Self::Data(Shape::W1),
            "W2" => Self::Data(Shape::W2),
            "W3" => Self::Data(Shape::W3),
            "W4" => Self::Data(Shape::W4),
            "W5" => Self::Data(Shape::W5),
            "ctl152" => Self::Control,
            "rekey" => Self::Rekey,
            other => return Err(BenchError(format!("unknown point {other}"))),
        })
    }

    /// Its name.
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Self::Data(shape) => shape.to_string(),
            Self::Control => "ctl152".to_string(),
            Self::Rekey => "rekey".to_string(),
        }
    }

    /// The key domain of the point.
    #[must_use]
    pub fn domain(self) -> Domain {
        match self {
            Self::Control => Domain::Receiver,
            Self::Data(_) | Self::Rekey => Domain::Sender,
        }
    }

    /// The inner frame bytes of one datagram.
    ///
    /// # Errors
    ///
    /// A shape without a single-datagram size at [`E`].
    pub fn frames(self) -> Result<usize, BenchError> {
        match self {
            Self::Control => Ok(CONTROL_BYTES),
            Self::Rekey => Self::Data(Shape::W1).frames(),
            Self::Data(shape) => {
                let size = shape
                    .size(E, MtuRule::CountsEnvelope)
                    .map_err(|e| BenchError(e.to_string()))?;
                let frame = HEADER
                    .checked_add(size.payload)
                    .and_then(|n| n.checked_add(ALIGNMENT - 1))
                    .map(|n| n - n % ALIGNMENT)
                    .and_then(|n| n.checked_mul(size.frames_per_datagram))
                    .ok_or_else(|| BenchError("frame bytes overflow".to_string()))?;
                if size.datagrams_per_message != 1 {
                    return Err(BenchError(format!("{shape} is not one datagram")));
                }
                usize::try_from(frame).map_err(|_| BenchError("frame bytes".to_string()))
            }
        }
    }
}

/// The profile of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// The trusted channel, the baseline.
    Trusted,
    /// AES-256-GCM-SIV (ADR-0114).
    Encrypted,
}

impl Profile {
    /// The profile `name` names: `trusted` or `encrypted`.
    ///
    /// # Errors
    ///
    /// Any other name.
    pub fn of(name: &str) -> Result<Self, BenchError> {
        match name {
            "trusted" => Ok(Self::Trusted),
            "encrypted" => Ok(Self::Encrypted),
            other => Err(BenchError(format!("unknown profile {other}"))),
        }
    }

    /// Its name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Encrypted => "encrypted",
        }
    }
}

/// Nearest-rank quantiles and the mean of one series, in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Quantiles {
    /// Samples.
    pub n: usize,
    /// p50.
    pub p50: u64,
    /// p99.
    pub p99: u64,
    /// p99.9, the value at rank `ceil(0.999 n)` (manifest 8.3 (a)).
    pub p999: u64,
    /// Mean.
    pub mean: f64,
}

impl Quantiles {
    /// The quantiles of `samples`, which it sorts.
    #[must_use]
    pub fn of(samples: &mut [u64]) -> Self {
        samples.sort_unstable();
        let n = samples.len();
        let rank = |per_mille: usize| {
            let r = n.saturating_mul(per_mille).div_ceil(1000).max(1);
            samples.get(r - 1).copied().unwrap_or_default()
        };
        let sum: u128 = samples.iter().map(|&v| u128::from(v)).sum();
        #[allow(clippy::cast_precision_loss)]
        let mean = if n == 0 { 0.0 } else { sum as f64 / n as f64 };
        Self {
            n,
            p50: rank(500),
            p99: rank(990),
            p999: rank(999),
            mean,
        }
    }
}

/// The series of one run: one row per operation.
#[derive(Debug, Clone, PartialEq)]
pub struct Run {
    /// The point.
    pub point: Point,
    /// The profile.
    pub profile: Profile,
    /// Inner frame bytes per datagram.
    pub frames: usize,
    /// Datagram bytes on the wire.
    pub datagram: usize,
    /// `(op, quantiles)`: `send`, `recv` and `both`, or `rekey`.
    pub ops: Vec<(&'static str, Quantiles)>,
}

impl Run {
    /// The CSV header of [`Run::csv`].
    pub const HEADER: &'static str = "backend,run,profile,point,domain,inner_bytes,datagram_bytes,op,n,p50_ns,p99_ns,p99_9_ns,mean_ns";

    /// Its CSV rows, labelled `backend` and run `run`.
    #[must_use]
    pub fn csv(&self, backend: &str, run: u32) -> String {
        let mut out = String::new();
        for (op, q) in &self.ops {
            out.push_str(&format!(
                "{backend},{run},{},{},{},{},{},{op},{},{},{},{},{:.1}\n",
                self.profile.name(),
                self.point.name(),
                self.point.domain() as u8,
                self.frames,
                self.datagram,
                q.n,
                q.p50,
                q.p99,
                q.p999,
                q.mean
            ));
        }
        out
    }
}

const IKM: [u8; 32] = [0x5a; 32];
const PAIRWISE_SECRET: [u8; 32] = [0xa5; 32];

fn publication() -> PublicationIdentity {
    PublicationIdentity {
        driver_id: [0x11; 16],
        registration_id: 7,
        incarnation: 3,
    }
}

fn receiver() -> ReceiverIdentity {
    ReceiverIdentity {
        receiver_boot_id: [0x22; 16],
        receiver_id: 42,
    }
}

fn context(domain: Domain, party_epoch: u16) -> KeyContext {
    KeyContext {
        domain,
        key_epoch: 1,
        party_epoch,
        session_id: -2,
        stream_id: 1001,
        publication: publication(),
        receiver: domain.is_receiver().then(receiver),
        salt: Salt::Challenge {
            receiver_boot_id: receiver().receiver_boot_id,
            nonce: [0x33; 16],
        },
    }
}

/// The domain 1 DATA key of the measured establishment, the same in every
/// process that derives it: the sender seals and the receiver opens under
/// it (the wire harness's `encrypted` profile).
///
/// # Errors
///
/// A key that does not derive.
pub fn data_key() -> Result<AesGcmSiv, BenchError> {
    key(Domain::Sender)
}

fn key(domain: Domain) -> Result<AesGcmSiv, BenchError> {
    let pairwise = if domain.is_receiver() {
        vec![
            PairwiseKey::derive(&PAIRWISE_SECRET, 1, &receiver(), &publication())
                .map_err(|e| BenchError(e.to_string()))?,
        ]
    } else {
        Vec::new()
    };
    AesGcmSiv::new(&IKM, context(domain, 1), &pairwise).map_err(|e| BenchError(e.to_string()))
}

fn nanos(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Runs `warmup` untimed-in-results messages, then `samples` measured
/// ones, of `point` under `profile`.
///
/// # Errors
///
/// A seal or open that fails, which ends the run.
pub fn run(point: Point, profile: Profile, warmup: u64, samples: u64) -> Result<Run, BenchError> {
    let frames = point.frames()?;
    let total = warmup.saturating_add(samples);
    let capacity = usize::try_from(samples).map_err(|_| BenchError("samples".to_string()))?;
    let fail = |what: &str| BenchError(format!("{} {}: {what}", profile.name(), point.name()));
    if point == Point::Rekey {
        if profile == Profile::Trusted {
            return Err(fail("the trusted channel has no key to change"));
        }
        let mut sender = key(Domain::Sender)?;
        let mut series = Vec::with_capacity(capacity);
        for i in 0..total {
            let epoch = if i % 2 == 0 { 2 } else { 1 };
            let start = Instant::now();
            sender
                .rekey(black_box(&IKM), context(Domain::Sender, epoch), &[])
                .map_err(|e| fail(&e.to_string()))?;
            let elapsed = nanos(start);
            black_box(&sender);
            if i >= warmup {
                series.push(elapsed);
            }
        }
        return Ok(Run {
            point,
            profile,
            frames,
            datagram: 0,
            ops: vec![("rekey", Quantiles::of(&mut series))],
        });
    }
    let domain = point.domain();
    let (sender, opener) = match profile {
        Profile::Trusted => (None, None),
        Profile::Encrypted => (Some(key(domain)?), Some(key(domain)?)),
    };
    let template: Vec<u8> = (0..frames)
        .map(|i| u8::try_from(i % 251).unwrap_or_default())
        .collect();
    let mut tx = [0_u8; MAX_DATAGRAM];
    let mut rx = [0_u8; MAX_DATAGRAM];
    let mut send = Vec::with_capacity(capacity);
    let mut recv = Vec::with_capacity(capacity);
    let mut both = Vec::with_capacity(capacity);
    let mut datagram = 0;
    for i in 0..total {
        tx.get_mut(..frames)
            .ok_or_else(|| fail("frames exceed the datagram"))?
            .copy_from_slice(&template);
        let start = Instant::now();
        let sealed = match &sender {
            Some(key) => key.seal_next(black_box(&mut tx), frames).ok(),
            None => Trusted.seal(black_box(&mut tx), frames).ok(),
        };
        let sent = nanos(start);
        let len = sealed.ok_or_else(|| fail("seal refused"))?;
        datagram = len;
        let (Some(from), Some(to)) = (tx.get(..len), rx.get_mut(..len)) else {
            return Err(fail("datagram exceeds the buffer"));
        };
        to.copy_from_slice(from);
        let start = Instant::now();
        let accepted = match &opener {
            Some(key) => key
                .open_in_place(black_box(to))
                .and_then(|opened| key.mark(opened.seq))
                .is_ok(),
            None => matches!(Trusted.open(black_box(to)), Verdict::Accept { .. }),
        };
        let received = nanos(start);
        if !accepted {
            return Err(fail("open refused"));
        }
        if i >= warmup {
            send.push(sent);
            recv.push(received);
            both.push(sent.saturating_add(received));
        }
    }
    Ok(Run {
        point,
        profile,
        frames,
        datagram,
        ops: vec![
            ("send", Quantiles::of(&mut send)),
            ("recv", Quantiles::of(&mut recv)),
            ("both", Quantiles::of(&mut both)),
        ],
    })
}

/// The envelope bytes a datagram of `domain` adds: [`ENVELOPE_LEN`], and
/// the pairwise trailer in domain 4.
#[must_use]
pub fn overhead(domain: Domain) -> usize {
    if domain.is_receiver() {
        ENVELOPE_LEN + TRAILER_LEN
    } else {
        ENVELOPE_LEN
    }
}

/// Refuses the allocation build (`alloc-count`, M-9) as `measure` does:
/// its counting allocator is never timed, so `enc-cost` measures only in a
/// timing build. `alloc_count` is whether this binary is one.
///
/// # Errors
///
/// The refusal, when `alloc_count` holds.
pub fn timing_build(alloc_count: bool) -> Result<(), BenchError> {
    if alloc_count {
        return Err(BenchError(
            "this is the allocation build (alloc-count): it never measures timing".to_string(),
        ));
    }
    Ok(())
}

/// The build identity the CSV header is preceded by, as a `#` comment
/// line: the crate version, the build ([`crate::wire::stage::BUILD`]:
/// timing or alloc-count, synthetic or not), whether `test-hooks` is on,
/// the optimisation, the target and the CPU's AES instructions the
/// AES-GCM-SIV backend selects at run time (`aes-ni+pclmulqdq` or
/// `armv8-aes` for the hardware backend, else `soft`).
#[must_use]
pub fn build_identity() -> String {
    format!(
        "# karyos-bench {} enc-cost build={} test-hooks={} opt={} target={}-{} cpu-aes={}",
        env!("CARGO_PKG_VERSION"),
        crate::wire::stage::BUILD,
        cfg!(feature = "test-hooks"),
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        std::env::consts::ARCH,
        std::env::consts::OS,
        cpu_aes(),
    )
}

/// The AES instructions of this CPU the backend can use.
fn cpu_aes() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("aes")
        && std::arch::is_x86_feature_detected!("pclmulqdq")
    {
        return "aes-ni+pclmulqdq";
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("aes") {
        return "armv8-aes";
    }
    "soft"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allocation_build_never_times_and_the_identity_names_the_build() {
        assert!(timing_build(true).is_err());
        assert!(timing_build(false).is_ok());
        let identity = build_identity();
        assert!(identity.starts_with("# karyos-bench "), "{identity}");
        assert!(
            identity.contains(&format!(" build={} ", crate::wire::stage::BUILD)),
            "{identity}"
        );
        assert!(identity.contains(" cpu-aes="), "{identity}");
        assert!(!identity.contains('\n'), "{identity}");
    }

    #[test]
    fn every_point_runs_under_both_profiles() -> Result<(), BenchError> {
        for name in ["W1", "W2", "W3", "W4", "W5", "ctl152"] {
            let point = Point::of(name)?;
            for profile in [Profile::Trusted, Profile::Encrypted] {
                let run = run(point, profile, 10, 100)?;
                let extra = match profile {
                    Profile::Trusted => 0,
                    Profile::Encrypted => overhead(point.domain()),
                };
                assert_eq!(run.datagram, run.frames + extra, "{name}");
                assert!(run.datagram <= MAX_DATAGRAM);
                assert_eq!(run.ops.len(), 3);
                for (_, q) in &run.ops {
                    assert_eq!(q.n, 100);
                    assert!(q.p50 <= q.p99 && q.p99 <= q.p999);
                }
                assert_eq!(run.csv("accel", 1).lines().count(), 3);
            }
        }
        let rekey = run(Point::Rekey, Profile::Encrypted, 2, 10)?;
        assert_eq!(rekey.ops.len(), 1);
        assert!(run(Point::Rekey, Profile::Trusted, 0, 1).is_err());
        Ok(())
    }

    #[test]
    fn sizes_follow_the_manifest_at_e_84() -> Result<(), BenchError> {
        // W4: align_down(1408 - 84, 32) - 32 = 1280 payload, one 1312 frame;
        // W5: floor(1324 / 64) = 20 frames of 64.
        assert_eq!(Point::of("W1")?.frames()?, 64);
        assert_eq!(Point::of("W2")?.frames()?, 32);
        assert_eq!(Point::of("W3")?.frames()?, 288);
        assert_eq!(Point::of("W4")?.frames()?, 1312);
        assert_eq!(Point::of("W5")?.frames()?, 1280);
        assert_eq!(overhead(Domain::Sender), 84);
        assert_eq!(overhead(Domain::Receiver), 104);
        Ok(())
    }

    #[test]
    fn nearest_rank() {
        let mut v: Vec<u64> = (1..=1000).rev().collect();
        let q = Quantiles::of(&mut v);
        assert_eq!((q.p50, q.p99, q.p999), (500, 990, 999));
    }
}

/// The seals the R5 sender makes under the starting key before its
/// in-band epoch change, and under that key before the file epoch change:
/// a third and two thirds of a decision run with its warmup (karyos#650).
pub const ROTATION_AT: [u64; 2] = [366_667, 733_334];

/// The keys of an R5 run (karyos#650, manifest 6.1 R5): the starting key
/// (file epoch 1, in-band epoch 1), its in-band successor (in-band epoch
/// 2) and the next file epoch's key (file epoch 2, in-band epoch 1), each
/// derived before the run, as the driver derives a successor ahead of its
/// cutover. The sender seals under each in turn at [`ROTATION_AT`]; the
/// receiver opens under the key the datagram's header names. The
/// derivation's own cost is the `rekey` point of this module.
#[derive(Debug)]
pub struct Rotation {
    keys: [AesGcmSiv; 3],
    sealed: std::sync::atomic::AtomicU64,
}

impl Rotation {
    /// The three keys.
    ///
    /// # Errors
    ///
    /// A key that does not derive.
    pub fn new() -> Result<Self, BenchError> {
        let derive = |key_epoch: u32, party_epoch: u16| {
            let context = KeyContext {
                key_epoch,
                ..context(Domain::Sender, party_epoch)
            };
            AesGcmSiv::new(&IKM, context, &[]).map_err(|e| BenchError(e.to_string()))
        };
        Ok(Self {
            keys: [derive(1, 1)?, derive(1, 2)?, derive(2, 1)?],
            sealed: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Moves the sender to seal `n` next (tests).
    #[cfg(test)]
    fn skip_to(&self, n: u64) {
        self.sealed.store(n, std::sync::atomic::Ordering::Relaxed);
    }

    /// The key the next seal uses.
    fn sealer(&self) -> &AesGcmSiv {
        let n = self
            .sealed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let index = ROTATION_AT.iter().filter(|&&at| n >= at).count();
        let [first, second, third] = &self.keys;
        match index {
            0 => first,
            1 => second,
            _ => third,
        }
    }

    /// The key `datagram`'s header names (`key_epoch` at 12, `party_epoch`
    /// at 16), if it is one of the run's.
    #[must_use]
    pub fn opener(&self, datagram: &[u8]) -> Option<&AesGcmSiv> {
        let key_epoch = u32::from_le_bytes(datagram.get(12..16)?.try_into().ok()?);
        let party_epoch = u16::from_le_bytes(datagram.get(16..18)?.try_into().ok()?);
        match (key_epoch, party_epoch) {
            (1, 1) => self.keys.first(),
            (1, 2) => self.keys.get(1),
            (2, 1) => self.keys.get(2),
            _ => None,
        }
    }
}

impl Protection for Rotation {
    fn envelope_len(&self) -> usize {
        let [first, ..] = &self.keys;
        first.envelope_len()
    }

    fn seal(
        &self,
        datagram: &mut [u8],
        frames: usize,
    ) -> Result<usize, karyos_protocol::protection::SealError> {
        self.sealer().seal(datagram, frames)
    }

    fn open(&self, datagram: &[u8]) -> Verdict {
        match self.opener(datagram) {
            Some(key) => key.open(datagram),
            None => Verdict::Reject(karyos_protocol::protection::Rejection::Short),
        }
    }
}

#[cfg(test)]
mod rotation_tests {
    use super::*;

    /// R5 (karyos#650): the sender's seals cross one in-band and one file
    /// epoch change at [`ROTATION_AT`]; the receiver opens each datagram
    /// under the key its header names, and a datagram of an unknown epoch
    /// is refused.
    #[test]
    fn a_rotation_crosses_an_in_band_and_a_file_epoch_and_every_datagram_opens() {
        let sender = Rotation::new().unwrap();
        let receiver = Rotation::new().unwrap();
        let mut epochs = Vec::new();
        for at in [0, ROTATION_AT[0], ROTATION_AT[1]] {
            sender.skip_to(at);
            let mut datagram = vec![0_u8; 1408];
            datagram[..64].fill(3);
            let length = sender.seal(&mut datagram, 64).unwrap();
            let datagram = &datagram[..length];
            epochs.push((
                u32::from_le_bytes(datagram[12..16].try_into().unwrap()),
                u16::from_le_bytes(datagram[16..18].try_into().unwrap()),
            ));
            assert!(
                matches!(receiver.open(datagram), Verdict::Accept { .. }),
                "{at}"
            );
        }
        assert_eq!(epochs, [(1, 1), (1, 2), (2, 1)]);
        let mut foreign = vec![0_u8; 128];
        foreign[12] = 9;
        assert!(matches!(receiver.open(&foreign), Verdict::Reject(_)));
    }
}
