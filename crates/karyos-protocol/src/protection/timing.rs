// SPDX-License-Identifier: Apache-2.0

//! The timing harness of gate H7, constant time (tests only;
//! `quantstratum-docs: karyos/design/wire-threat-model-manifest.md`: a
//! review of the comparison, with a statistical timing test as supporting
//! evidence, not proof). Shared by every protection class's H7 tests.
//!
//! [`compare`] is a dudect-style test of one operation over two classes of
//! inputs, held alike in one preallocated array of [`SLOTS`] slots made
//! before any timing; each sample's slot is drawn from a fixed seed, and
//! only the operation is timed. Welch's t
//! is computed on the raw timings and on [`CROPS`] percentile crops of the
//! pooled timings, as dudect sets them. [`Report::assert_constant_time`]
//! reports every `t`, the median duration and the clock's measured tick
//! on stdout, and fails when the clock does not resolve the operation
//! (median below [`RESOLUTION_FACTOR`] ticks) or any `|t|` reaches
//! [`THRESHOLD`]; [`Report::print`] reports a comparison that is measured
//! and not gated.
//!
//! Environment:
//!
//! - `KARYOS_H7_SAMPLES`: samples per class ([`samples`], default
//!   1 000 000);
//! - `KARYOS_H7_EXPECT_ACCEL=1`: [`expect_accelerated`] fails unless the
//!   AEAD crates take their accelerated backends (set on xaskar and
//!   studiom4).
//!
//! Only `#[ignore]`d statistical tests may call [`Report::print`] or
//! [`Report::assert_constant_time`]: the normal suite stays silent. Run them
//! with `--release --nocapture --test-threads=1` on an idle host.

#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]

use std::hint::black_box;
use std::io::Write as _;
use std::time::Instant;

/// The dudect threshold: a gated `|t|` at or above it fails.
pub(crate) const THRESHOLD: f64 = 4.5;

/// Percentile crops besides the raw timings.
pub(crate) const CROPS: usize = 10;

/// The default samples per class.
pub(crate) const DEFAULT_SAMPLES: usize = 1_000_000;

/// xorshift64*: reproducible inputs and class order without a dependency.
#[derive(Debug, Clone)]
pub(crate) struct Rng(u64);

impl Rng {
    /// A generator from `seed` (a zero seed is replaced: xorshift needs a
    /// nonzero state).
    pub(crate) fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    /// The next word.
    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Fills `bytes`.
    pub(crate) fn fill(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }
}

/// One of the two input classes of a comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    /// The first class (dudect's "fixed" class, by convention).
    A,
    /// The second class (dudect's "random" class, by convention).
    B,
}

/// A gated operation's median must be at least this many clock ticks, so
/// that the clock resolves differences well below the operation itself.
pub(crate) const RESOLUTION_FACTOR: u64 = 100;

/// The clock's resolution: the smallest nonzero step between successive
/// [`Instant::now`] readings over a short run, in nanoseconds (about 41 ns
/// on macOS, a few tens of ns or less on Linux). Each gated sample spans
/// at least [`RESOLUTION_FACTOR`] of them.
pub(crate) fn resolution_ns() -> u64 {
    let mut smallest = u64::MAX;
    for _ in 0..10_000 {
        let start = Instant::now();
        let mut now = Instant::now();
        while now == start {
            now = Instant::now();
        }
        let step = u64::try_from(now.duration_since(start).as_nanos()).unwrap_or(u64::MAX);
        smallest = smallest.min(step);
    }
    smallest
}

/// Samples per class: `KARYOS_H7_SAMPLES`, or [`DEFAULT_SAMPLES`].
pub(crate) fn samples() -> usize {
    std::env::var("KARYOS_H7_SAMPLES")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(DEFAULT_SAMPLES)
}

/// The result of one [`compare`].
#[derive(Debug, Clone)]
pub(crate) struct Report {
    /// The comparison's name.
    pub(crate) name: String,
    /// Welch's t on the raw timings, then on each percentile crop.
    pub(crate) t: Vec<f64>,
    /// The median timed duration of one sample (a batch of `reps`
    /// operations), in nanoseconds.
    pub(crate) median_ns: u64,
    /// The clock's resolution as measured ([`resolution_ns`]).
    pub(crate) tick_ns: u64,
    /// Operations timed per sample: chosen at the start, doubled from 1
    /// until the median batch spans [`RESOLUTION_FACTOR`] ticks (at most
    /// [`MAX_REPS`]).
    pub(crate) reps: u32,
}

impl Report {
    /// The largest `|t|` over the raw timings and every crop.
    pub(crate) fn max_abs_t(&self) -> f64 {
        self.t.iter().fold(0.0_f64, |max, t| max.max(t.abs()))
    }

    /// Whether every `|t|` is below [`THRESHOLD`].
    pub(crate) fn is_constant_time(&self) -> bool {
        self.max_abs_t() < THRESHOLD
    }

    /// Whether the clock resolves the operation: its median is at least
    /// [`RESOLUTION_FACTOR`] clock ticks.
    pub(crate) fn is_resolved(&self) -> bool {
        self.median_ns >= RESOLUTION_FACTOR.saturating_mul(self.tick_ns.max(1))
    }

    fn line(&self, gated: bool) -> String {
        let timing = format!(
            "{} reps per sample, median {} ns per sample ({} ns per op), clock tick {} ns",
            self.reps,
            self.median_ns,
            self.median_ns / u64::from(self.reps.max(1)),
            self.tick_ns
        );
        if !self.is_resolved() {
            return format!(
                "H7 {} ({}): unresolved, the median sample is below {RESOLUTION_FACTOR} \
                 clock ticks; {timing}",
                self.name,
                if gated { "gated" } else { "measured" },
            );
        }
        let values: Vec<String> = self.t.iter().map(|t| format!("{t:.2}")).collect();
        format!(
            "H7 {} ({}): max |t| = {:.2}; t = [{}]; {timing}",
            self.name,
            if gated { "gated" } else { "measured" },
            self.max_abs_t(),
            values.join(", "),
        )
    }

    /// Reports it on stdout as measured, not gated (ignored tests only).
    pub(crate) fn print(&self) {
        let _ = writeln!(std::io::stdout(), "{}", self.line(false));
    }

    /// Reports it on stdout and fails when any `|t|` reaches
    /// [`THRESHOLD`] (ignored tests only).
    pub(crate) fn assert_constant_time(&self) {
        let line = self.line(true);
        let _ = writeln!(std::io::stdout(), "{line}");
        assert!(
            self.is_resolved(),
            "H7 the clock does not resolve the operation: {line}"
        );
        assert!(self.is_constant_time(), "H7 |t| >= {THRESHOLD}: {line}");
    }
}

/// Input slots a comparison holds, half of each class: every sample
/// times the operation on one of them, so both classes' inputs are held
/// alike (same type, size and allocation, one array) and cycle through the
/// caches alike.
pub(crate) const SLOTS: usize = 4096;

/// The most operations timed per sample.
pub(crate) const MAX_REPS: u32 = 1 << 16;

/// Batches of the calibration of [`compare`]'s repetitions.
const CALIBRATION: usize = 101;

/// Times `run` over about `samples` inputs of each class.
///
/// Before any timing: [`SLOTS`] inputs are made by `input`, half of each
/// class in an order drawn from `seed`, into one array, and the slot of
/// every sample is drawn from `seed` too. Each sample then calls `setup`
/// on its slot untimed and times a batch of `reps` runs of `run` on that
/// same slot, `reps` chosen at the start so that the clock resolves the
/// batch (for example `setup` copies the slot into a shared work buffer
/// both classes use) and times only `run` on it: nothing is allocated,
/// dropped or drawn near the timed region. `run` returns whether the
/// operation gave the class's expected result, and a sample that did not
/// fails the comparison: a timing test of the wrong operation proves
/// nothing.
pub(crate) fn compare<T>(
    name: &str,
    seed: u64,
    samples: usize,
    mut input: impl FnMut(Class, &mut Rng) -> T,
    mut setup: impl FnMut(&T),
    mut run: impl FnMut(&T) -> bool,
) -> Report {
    let mut order = Rng::new(seed);
    let mut inputs = Rng::new(seed.rotate_left(32) ^ 0xD1B5_4A32_D192_ED03);
    let mut classes: Vec<Class> = (0..SLOTS)
        .map(|at| if at % 2 == 0 { Class::A } else { Class::B })
        .collect();
    for at in (1..classes.len()).rev() {
        let other = usize::try_from(order.next_u64() % (at as u64 + 1)).unwrap_or(0);
        classes.swap(at, other);
    }
    let slots: Vec<(Class, T)> = classes
        .into_iter()
        .map(|class| (class, input(class, &mut inputs)))
        .collect();
    let picks: Vec<u32> = (0..samples.saturating_mul(2))
        .map(|_| u32::try_from(order.next_u64() % SLOTS as u64).unwrap_or(0))
        .collect();
    let tick = resolution_ns();
    // One sample: `setup` once, untimed, then `reps` runs on the same
    // slot, timed together.
    let mut batch = |value: &T, reps: u32| -> (bool, u64) {
        setup(value);
        let mut expected = true;
        let start = Instant::now();
        for _ in 0..reps {
            expected &= black_box(run(black_box(value)));
        }
        let elapsed = start.elapsed();
        (
            expected,
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
        )
    };
    // Calibration: double the repetitions until the median batch, over
    // slots of both classes, spans 1.5 times the resolution factor in ticks.
    let mut reps = 1_u32;
    loop {
        let mut durations: Vec<u64> = (0..CALIBRATION)
            .map(|at| batch(&slots[at % SLOTS].1, reps).1)
            .collect();
        durations.sort_unstable();
        let median = durations[CALIBRATION / 2];
        // A margin over the factor: the run's median may fall a little
        // below the calibration's.
        let target = RESOLUTION_FACTOR
            .saturating_mul(tick.max(1))
            .saturating_mul(3)
            / 2;
        if median >= target || reps >= MAX_REPS {
            break;
        }
        reps = reps.saturating_mul(2);
    }
    let mut timed: Vec<(Class, u64)> = Vec::with_capacity(picks.len());
    for at in picks {
        let (class, value) = &slots[at as usize];
        let (expected, elapsed) = batch(value, reps);
        assert!(
            expected,
            "H7 {name}: a {class:?} sample gave another result"
        );
        timed.push((*class, elapsed));
    }
    let mut durations: Vec<u64> = timed.iter().map(|(_, ns)| *ns).collect();
    durations.sort_unstable();
    Report {
        name: name.to_owned(),
        t: t_values(&timed),
        median_ns: durations.get(durations.len() / 2).copied().unwrap_or(0),
        tick_ns: tick,
        reps,
    }
}

/// Running mean and variance (Welford).
#[derive(Debug, Default, Clone, Copy)]
struct Moments {
    n: f64,
    mean: f64,
    m2: f64,
}

impl Moments {
    fn push(&mut self, x: f64) {
        self.n += 1.0;
        let delta = x - self.mean;
        self.mean += delta / self.n;
        self.m2 += delta * (x - self.mean);
    }

    fn variance(&self) -> f64 {
        if self.n < 2.0 {
            0.0
        } else {
            self.m2 / (self.n - 1.0)
        }
    }
}

/// Welch's t between two classes.
fn welch(a: Moments, b: Moments) -> f64 {
    let se = (a.variance() / a.n + b.variance() / b.n).sqrt();
    if se == 0.0 || !se.is_finite() {
        0.0
    } else {
        (a.mean - b.mean) / se
    }
}

/// Welch's t on the raw timings, then on the samples at or below each of
/// [`CROPS`] percentiles of the pooled timings (`1 - 0.5^(10 (i + 1) /
/// CROPS)`, as dudect).
fn t_values(samples: &[(Class, u64)]) -> Vec<f64> {
    let mut pooled: Vec<u64> = samples.iter().map(|(_, ns)| *ns).collect();
    pooled.sort_unstable();
    let mut limits = vec![u64::MAX];
    for i in 0..CROPS {
        let percentile = 1.0 - 0.5_f64.powf(10.0 * (i as f64 + 1.0) / CROPS as f64);
        let at = ((pooled.len().saturating_sub(1)) as f64 * percentile) as usize;
        limits.push(pooled.get(at).copied().unwrap_or(u64::MAX));
    }
    limits
        .into_iter()
        .map(|limit| {
            let (mut a, mut b) = (Moments::default(), Moments::default());
            for (class, ns) in samples {
                if *ns <= limit {
                    match class {
                        Class::A => a.push(*ns as f64),
                        Class::B => b.push(*ns as f64),
                    }
                }
            }
            welch(a, b)
        })
        .collect()
}

/// Which AES and POLYVAL backends `aes` 0.9 and `polyval` 0.7 take here.
#[derive(Debug, Clone)]
pub(crate) struct Backends {
    /// `aes` takes its accelerated backend: AES-NI on x86_64, AES on
    /// aarch64, and not forced soft (`--cfg aes_backend="soft"`).
    pub(crate) aes: bool,
    /// `polyval` takes its accelerated backend: AVX with PCLMULQDQ on
    /// x86_64, AES (the crate's PMULL test) on aarch64, and not forced soft
    /// (`--cfg polyval_backend="soft"`).
    pub(crate) polyval: bool,
    /// The detected features and the selection, for the report.
    pub(crate) line: String,
}

/// The backends, by the crates' own `cpufeatures` feature names, read
/// through the standard library's detection of the same features.
#[expect(
    unexpected_cfgs,
    reason = "the backend cfgs are the crates' own, set only through RUSTFLAGS"
)]
pub(crate) fn backends() -> Backends {
    let forced_aes = cfg!(aes_backend = "soft");
    let forced_polyval = cfg!(polyval_backend = "soft");
    #[cfg(target_arch = "x86_64")]
    let (aes, polyval, features) = {
        let aes = std::arch::is_x86_feature_detected!("aes");
        let avx = std::arch::is_x86_feature_detected!("avx");
        let clmul = std::arch::is_x86_feature_detected!("pclmulqdq");
        let vaes = std::arch::is_x86_feature_detected!("vaes");
        (
            aes,
            avx && clmul,
            format!("x86_64 aes={aes} avx={avx} pclmulqdq={clmul} vaes={vaes}"),
        )
    };
    #[cfg(target_arch = "aarch64")]
    let (aes, polyval, features) = {
        let aes = std::arch::is_aarch64_feature_detected!("aes");
        let pmull = std::arch::is_aarch64_feature_detected!("pmull");
        (aes, aes, format!("aarch64 aes={aes} pmull={pmull}"))
    };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let (aes, polyval, features) = (false, false, String::from("other target"));
    let aes = aes && !forced_aes;
    let polyval = polyval && !forced_polyval;
    let name = |accelerated: bool| if accelerated { "accelerated" } else { "soft" };
    Backends {
        aes,
        polyval,
        line: format!(
            "{features}; forced soft: aes={forced_aes} polyval={forced_polyval}; \
             selected: aes={} polyval={}",
            name(aes),
            name(polyval)
        ),
    }
}

/// Fails unless both backends are accelerated, when
/// `KARYOS_H7_EXPECT_ACCEL=1`; otherwise only computes them. Returns them.
pub(crate) fn expect_accelerated() -> Backends {
    let backends = backends();
    if std::env::var("KARYOS_H7_EXPECT_ACCEL").as_deref() == Ok("1") {
        assert!(
            backends.aes && backends.polyval,
            "expected accelerated backends: {}",
            backends.line
        );
    }
    backends
}

/// Reports the backends on stdout (ignored tests only).
pub(crate) fn print_backends() {
    let _ = writeln!(std::io::stdout(), "H7 backend: {}", backends().line);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn welch_t_separates_a_shift_and_not_identical_classes() {
        let same: Vec<(Class, u64)> = (0..2000_u64)
            .map(|i| {
                (
                    if i % 2 == 0 { Class::A } else { Class::B },
                    100 + (i / 2) % 7,
                )
            })
            .collect();
        assert!(t_values(&same).iter().all(|t| t.abs() < 1.0));
        let shifted: Vec<(Class, u64)> = (0..2000_u64)
            .map(|i| {
                let class = if i % 2 == 0 { Class::A } else { Class::B };
                (
                    class,
                    100 + (i / 2) % 7 + if class == Class::B { 50 } else { 0 },
                )
            })
            .collect();
        assert!(t_values(&shifted)[0].abs() > 100.0);
        assert_eq!(t_values(&shifted).len(), CROPS + 1);
    }

    #[test]
    fn compare_holds_both_classes_and_checks_every_result() {
        let mut seen = [0_usize; 2];
        let report = compare(
            "harness",
            7,
            1000,
            |class, rng| (class, rng.next_u64()),
            |_| {},
            |(class, _)| {
                seen[usize::from(*class == Class::B)] += 1;
                true
            },
        );
        // Calibration and every sample run `reps` times each.
        let reps = usize::try_from(report.reps).unwrap();
        assert!(seen[0] + seen[1] >= 2000 * reps);
        assert!(seen[0] > 800 * reps && seen[1] > 800 * reps, "{seen:?}");
        // Calibration doubles from 1 and stops at `MAX_REPS`; whether the
        // clock resolved the batch depends on the host's load, not on the
        // harness, so it is not asserted here.
        assert!((1..=MAX_REPS).contains(&report.reps), "{}", report.reps);
        assert!(report.reps.is_power_of_two(), "{}", report.reps);
        assert_eq!(report.t.len(), CROPS + 1);
        assert!(report.t.iter().all(|t| t.is_finite()));
    }

    /// The A/A check of the harness on real timings: both classes run the
    /// same operation on equal inputs, so every `|t|` stays below the
    /// threshold (ignored: a timing test).
    #[test]
    #[ignore = "statistical timing test: run on an idle host"]
    fn h7_identical_classes_give_no_signal() {
        // As the protection tests: each sample's input is copied into one
        // shared buffer untimed, and only that buffer is read timed.
        let work = std::cell::RefCell::new(vec![0_u8; 1024]);
        let report = compare(
            "identical classes",
            11,
            samples(),
            |_, _| vec![0x5A_u8; 1024],
            |bytes| work.borrow_mut().copy_from_slice(bytes),
            |_| {
                let bytes = work.borrow();
                let sum = bytes.iter().fold(0_u64, |sum, byte| {
                    sum.wrapping_mul(31).wrapping_add(u64::from(*byte))
                });
                black_box(sum) != 1
            },
        );
        report.assert_constant_time();
    }

    #[test]
    fn the_clock_resolution_is_measured() {
        let tick = resolution_ns();
        assert!(tick > 0 && tick < 1_000_000, "{tick} ns");
    }

    #[test]
    #[should_panic(expected = "gave another result")]
    fn a_wrong_result_fails_the_comparison() {
        let _ = compare(
            "wrong",
            1,
            10,
            |class, _| class,
            |_| {},
            |class| *class == Class::A,
        );
    }
}
