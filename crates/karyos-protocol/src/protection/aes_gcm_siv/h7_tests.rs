// SPDX-License-Identifier: Apache-2.0

//! Gate H7, constant time, for the `encrypted` class
//! (`quantstratum-docs: karyos/adr/0114-encrypted-protection-profile-v1.md`,
//! "Hard gates" and "To verify"), on the shared harness
//! [`crate::protection::timing`].
//!
//! Review: `aes-gcm-siv` 0.12.1 compares the tag with `ctutils::CtEq`
//! (`decrypt_inout_detached`), and on a mismatch runs its keystream over
//! the buffer again. [`AesGcmSiv::open_into`] reads only header fields
//! before the AEAD, decrypts into the caller's separate buffer and erases
//! it on any failure; nothing branches on a tag byte before the crate's
//! comparison.
//!
//! The fast tests run in the normal suite and are silent: no failed open
//! releases plaintext or moves state, whichever tag byte or ciphertext bit
//! differs; and the backends the crates take are the accelerated ones
//! (AES-NI and AVX with PCLMULQDQ on x86_64; AES, which the crates also
//! take as PMULL, on aarch64) when `KARYOS_H7_EXPECT_ACCEL=1` is set, as
//! on xaskar and studiom4.
//!
//! The statistical tests are `#[ignore]`d. Gated (`|t|` below 4.5): invalid
//! tags differing in their first against their last byte; a fixed against
//! a random invalid tag; a valid open of a fixed against a random
//! plaintext; a seal of a fixed against a random plaintext. Measured and
//! not gated: a valid against an invalid tag. That one differs by design
//! (the crate's second keystream pass and the erase of the output on
//! failure), and whether a datagram was accepted is observable anyway, so
//! it leaks nothing an attacker does not already see.
//!
//! A run counts as H7 evidence only if, in that same run, the A/A control
//! (`h7_identical_classes_give_no_signal`) and the precheck step of the
//! bisection (header reads only) are both below 4.5; each gated sample
//! spans at least `timing::RESOLUTION_FACTOR` (100) clock ticks.
//!
//! Commands, on an otherwise idle host (`KARYOS_H7_SAMPLES` sets the
//! samples per class, default 1 000 000):
//!
//! - accelerated backends:
//!   `KARYOS_H7_EXPECT_ACCEL=1 cargo test -p karyos-protocol --release --lib -- --ignored h7_ --nocapture --test-threads=1`
//! - soft backends:
//!   `RUSTFLAGS='--cfg aes_backend="soft" --cfg polyval_backend="soft"' CARGO_TARGET_DIR=target-soft cargo test -p karyos-protocol --release --lib -- --ignored h7_ --nocapture --test-threads=1`

#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]

use std::hint::black_box;

use super::*;
use crate::protection::timing::{
    self, Class, Report, Rng, compare, expect_accelerated, print_backends,
};

/// Plaintext bytes of every measured datagram: a typical batch.
const FRAMES: usize = 1024;

fn key() -> AesGcmSiv {
    let context = KeyContext {
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
    };
    AesGcmSiv::new(&[0x5A; 32], context, &[]).unwrap()
}

/// `frames` sealed under `key` at `seq`.
fn sealed(key: &AesGcmSiv, frames: &[u8], seq: u64) -> Vec<u8> {
    let mut datagram = vec![0_u8; frames.len() + ENVELOPE_LEN];
    datagram[..frames.len()].copy_from_slice(frames);
    key.set_next_seq(seq);
    let total = key.seal_next(&mut datagram, frames.len()).unwrap();
    datagram.truncate(total);
    datagram
}

/// The offset of the tag: the last [`TAG_LEN`] bytes.
fn tag_at(datagram: &[u8]) -> usize {
    datagram.len() - TAG_LEN
}

fn opens_to_tag(key: &AesGcmSiv, datagram: &[u8], out: &mut [u8]) -> bool {
    key.open_into(black_box(datagram), out) == Err(EncRejection::Tag)
}

/// Every input of a comparison, both classes alike: one preallocated
/// array of [`timing::SLOTS`] slots of one stride, a fixed-class slot
/// simply holding the fixed value. Same addresses and layout for both
/// classes; only the content differs.
struct Arena {
    bytes: std::cell::RefCell<Vec<u8>>,
    /// The offset of slot 0 in `bytes`: the first cache line boundary.
    base: usize,
    /// The bytes of one value.
    len: usize,
    /// The distance between slots: `len` rounded up to [`LINE`], so every
    /// slot of either class starts on a cache line boundary and no slot
    /// shares a line with another.
    stride: usize,
    next: std::cell::Cell<usize>,
    /// One cache-line-aligned buffer every sample's value is copied into
    /// by the untimed setup ([`Arena::stage`]): the timed operation always
    /// reads the same address whatever the class, so the slots' own
    /// addresses (cache sets, pages, prefetch) cannot become a class
    /// difference.
    staged: std::cell::RefCell<Vec<u8>>,
    staged_base: usize,
}

/// The cache line every [`Arena`] slot is aligned to.
const LINE: usize = 128;

impl Arena {
    fn new(len: usize) -> Self {
        let stride = len.div_ceil(LINE) * LINE;
        let bytes = vec![0_u8; stride * timing::SLOTS + LINE];
        let base = bytes.as_ptr().align_offset(LINE);
        let staged = vec![0_u8; stride + LINE];
        let staged_base = staged.as_ptr().align_offset(LINE);
        Self {
            bytes: std::cell::RefCell::new(bytes),
            base,
            len,
            stride,
            next: std::cell::Cell::new(0),
            staged: std::cell::RefCell::new(staged),
            staged_base,
        }
    }

    /// Copies slot `at` into the staging buffer (untimed setup).
    fn stage(&self, at: usize) {
        let start = self.base + at * self.stride;
        let bytes = self.bytes.borrow();
        self.staged.borrow_mut()[self.staged_base..self.staged_base + self.len]
            .copy_from_slice(&bytes[start..start + self.len]);
    }

    /// The staged value (the timed run reads only this).
    fn staged(&self) -> std::cell::Ref<'_, [u8]> {
        let start = self.staged_base;
        std::cell::Ref::map(self.staged.borrow(), |bytes| {
            &bytes[start..start + self.len]
        })
    }

    /// Copies `value` into the next slot and returns the slot.
    fn push(&self, value: &[u8]) -> usize {
        assert_eq!(value.len(), self.len);
        let at = self.next.get();
        self.next.set(at + 1);
        let start = self.base + at * self.stride;
        self.bytes.borrow_mut()[start..start + self.len].copy_from_slice(value);
        at
    }
}

/// The output buffer every open of a comparison writes, both classes alike.
fn out() -> std::cell::RefCell<Vec<u8>> {
    std::cell::RefCell::new(vec![0_u8; MAX_PLAINTEXT])
}

/// The length of a sealed datagram of [`FRAMES`].
const SEALED: usize = FRAMES + ENVELOPE_LEN;

fn first_against_last(samples: usize) -> Report {
    let key = key();
    let good = sealed(&key, &[0x11; FRAMES], 1);
    let at = tag_at(&good);
    let (arena, out) = (Arena::new(SEALED), out());
    compare(
        "invalid tag, first byte against last byte",
        0x4831,
        samples,
        |class, _| {
            let mut bad = good.clone();
            match class {
                Class::A => bad[at] ^= 1,
                Class::B => bad[at + TAG_LEN - 1] ^= 1,
            }
            arena.push(&bad)
        },
        |slot| arena.stage(*slot),
        |_| opens_to_tag(&key, &arena.staged(), &mut out.borrow_mut()),
    )
}

fn fixed_against_random_tag(samples: usize) -> Report {
    let key = key();
    let good = sealed(&key, &[0x22; FRAMES], 1);
    let at = tag_at(&good);
    let (arena, out) = (Arena::new(SEALED), out());
    compare(
        "invalid tag, fixed against random",
        0x4832,
        samples,
        |class, rng: &mut Rng| {
            let mut bad = good.clone();
            match class {
                Class::A => bad[at] ^= 0x5A,
                Class::B => {
                    while bad[at..] == good[at..] {
                        rng.fill(&mut bad[at..]);
                    }
                }
            }
            arena.push(&bad)
        },
        |slot| arena.stage(*slot),
        |_| opens_to_tag(&key, &arena.staged(), &mut out.borrow_mut()),
    )
}

fn open_fixed_against_random(samples: usize) -> Report {
    let key = key();
    let (arena, out) = (Arena::new(SEALED), out());
    let mut seq = 1_u64;
    compare(
        "valid open, fixed against random plaintext",
        0x4834,
        samples,
        |class, rng| {
            let mut frames = [0x33_u8; FRAMES];
            if class == Class::B {
                rng.fill(&mut frames);
            }
            seq += 1;
            arena.push(&sealed(&key, &frames, seq))
        },
        |slot| arena.stage(*slot),
        |_| {
            key.open_into(black_box(&arena.staged()), &mut out.borrow_mut())
                .is_ok()
        },
    )
}

fn seal_fixed_against_random(samples: usize) -> Report {
    let key = key();
    let arena = Arena::new(FRAMES);
    let work = std::cell::RefCell::new(vec![0_u8; SEALED]);
    compare(
        "seal, fixed against random plaintext",
        0x4835,
        samples,
        |class, rng| {
            let mut frames = [0x44_u8; FRAMES];
            if class == Class::B {
                rng.fill(&mut frames);
            }
            arena.push(&frames)
        },
        |slot| arena.stage(*slot),
        // Every repetition seals the slot's own plaintext: the copy into
        // the shared work buffer is timed, the same for both classes.
        |_| {
            let mut held = work.borrow_mut();
            held[..FRAMES].copy_from_slice(&arena.staged());
            key.seal_next(black_box(&mut held[..]), FRAMES).is_ok()
        },
    )
}

fn valid_against_invalid(samples: usize) -> Report {
    let key = key();
    let good = sealed(&key, &[0x55; FRAMES], 1);
    let at = tag_at(&good);
    let (arena, out) = (Arena::new(SEALED), out());
    compare(
        "valid tag against invalid tag",
        0x4836,
        samples,
        |class, _| {
            let mut datagram = good.clone();
            if class == Class::B {
                datagram[at + TAG_LEN / 2] ^= 1;
            }
            (class, arena.push(&datagram))
        },
        |(_, slot)| arena.stage(*slot),
        |(class, _)| {
            let datagram = arena.staged();
            match class {
                Class::A => key
                    .open_into(black_box(&datagram), &mut out.borrow_mut())
                    .is_ok(),
                Class::B => opens_to_tag(&key, &datagram, &mut out.borrow_mut()),
            }
        },
    )
}

/// The bisection of a fixed against random plaintext, on valid
/// datagrams: each step of [`AesGcmSiv::open_into`] alone, the crate's
/// detached decrypt as our open calls it, the bare crate call outside our
/// envelope, and the same for the seal. Measured, not gated: it locates a
/// difference the gated tests find.
fn bisect(samples: usize) -> Vec<Report> {
    use ::aes_gcm_siv::aead::inout::InOutBuf;
    use ::aes_gcm_siv::aead::{AeadInOut, KeyInit};
    use ::aes_gcm_siv::{Aes256GcmSiv, Key, Nonce, Tag};

    let key = key();
    let (arena, out) = (Arena::new(SEALED), out());
    let mut seq = 1_u64;
    let mut inputs = Rng::new(0x4837);
    let mut made = Vec::new();
    let mut order = Rng::new(0x4838);
    let mut classes: Vec<Class> = (0..timing::SLOTS)
        .map(|at| if at % 2 == 0 { Class::A } else { Class::B })
        .collect();
    for at in (1..classes.len()).rev() {
        let other = usize::try_from(order.next_u64() % (at as u64 + 1)).unwrap();
        classes.swap(at, other);
    }
    for class in classes {
        let mut frames = [0x33_u8; FRAMES];
        if class == Class::B {
            inputs.fill(&mut frames);
        }
        seq += 1;
        made.push((class, arena.push(&sealed(&key, &frames, seq)), frames));
    }
    let by_class = |class: Class, rng: &mut Rng| -> usize {
        loop {
            let at = usize::try_from(rng.next_u64() % timing::SLOTS as u64).unwrap();
            if made[at].0 == class {
                return made[at].1;
            }
        }
    };
    let mut reports = Vec::new();
    reports.push(compare(
        "bisect open: precheck",
        0x4840,
        samples,
        by_class,
        |slot| arena.stage(*slot),
        |_| key.precheck(black_box(&arena.staged())).is_ok(),
    ));
    reports.push(compare(
        "bisect open: precheck, aad and nonce",
        0x4841,
        samples,
        by_class,
        |slot| arena.stage(*slot),
        |_| {
            let datagram = arena.staged();
            let Ok((seq, _)) = key.precheck(black_box(&datagram)) else {
                return false;
            };
            let header: &[u8; HEADER_LEN] = datagram[..HEADER_LEN].try_into().unwrap();
            black_box(associated_data(header));
            black_box(AesGcmSiv::nonce(key.context.domain, seq));
            true
        },
    ));
    reports.push(compare(
        "bisect open: crate detached decrypt as open_into calls it",
        0x4842,
        samples,
        by_class,
        |slot| arena.stage(*slot),
        |_| {
            let datagram = arena.staged();
            let Ok((seq, plaintext)) = key.precheck(&datagram) else {
                return false;
            };
            let header: &[u8; HEADER_LEN] = datagram[..HEADER_LEN].try_into().unwrap();
            let (body, tag) = datagram[HEADER_LEN..].split_at(plaintext);
            let tag = Tag::try_from(tag).unwrap();
            let aad = associated_data(header);
            let nonce = Nonce::from(AesGcmSiv::nonce(key.context.domain, seq));
            let mut held = out.borrow_mut();
            let buffer = InOutBuf::new(body, &mut held[..plaintext]).unwrap();
            key.aead
                .decrypt_inout_detached(&nonce, &aad, buffer, &tag)
                .is_ok()
        },
    ));
    reports.push(compare(
        "bisect open: open_into",
        0x4843,
        samples,
        by_class,
        |slot| arena.stage(*slot),
        |_| {
            key.open_into(black_box(&arena.staged()), &mut out.borrow_mut())
                .is_ok()
        },
    ));
    // The bare crate, outside our envelope: ciphertext and tag of each
    // slot's plaintext under one key and nonce, no associated data.
    let bare = Aes256GcmSiv::new(&Key::<Aes256GcmSiv>::from([0x5A; 32]));
    let nonce = Nonce::from([7_u8; 12]);
    let bare_arena = Arena::new(FRAMES + TAG_LEN);
    let mut bare_slots = Vec::new();
    for (class, _, frames) in &made {
        let mut body = *frames;
        let tag = bare
            .encrypt_inout_detached(&nonce, &[], InOutBuf::from(&mut body[..]))
            .unwrap();
        let mut slot = body.to_vec();
        slot.extend_from_slice(tag.as_slice());
        bare_slots.push((*class, bare_arena.push(&slot)));
    }
    let bare_by_class = |class: Class, rng: &mut Rng| -> usize {
        loop {
            let at = usize::try_from(rng.next_u64() % timing::SLOTS as u64).unwrap();
            if bare_slots[at].0 == class {
                return bare_slots[at].1;
            }
        }
    };
    reports.push(compare(
        "bisect open: bare Aes256GcmSiv detached decrypt",
        0x4844,
        samples,
        bare_by_class,
        |slot| bare_arena.stage(*slot),
        |_| {
            let held = bare_arena.staged();
            let (body, tag) = held.split_at(FRAMES);
            let tag = Tag::try_from(tag).unwrap();
            let mut target = out.borrow_mut();
            let buffer = InOutBuf::new(body, &mut target[..FRAMES]).unwrap();
            bare.decrypt_inout_detached(&nonce, &[], buffer, &tag)
                .is_ok()
        },
    ));
    let work = std::cell::RefCell::new(vec![0_u8; SEALED]);
    let plain_arena = Arena::new(FRAMES);
    let mut plain_slots = Vec::new();
    for (class, _, frames) in &made {
        plain_slots.push((*class, plain_arena.push(frames)));
    }
    let plain_by_class = |class: Class, rng: &mut Rng| -> usize {
        loop {
            let at = usize::try_from(rng.next_u64() % timing::SLOTS as u64).unwrap();
            if plain_slots[at].0 == class {
                return plain_slots[at].1;
            }
        }
    };
    reports.push(compare(
        "bisect seal: bare Aes256GcmSiv detached encrypt",
        0x4845,
        samples,
        plain_by_class,
        |slot| plain_arena.stage(*slot),
        |_| {
            let mut held = work.borrow_mut();
            held[..FRAMES].copy_from_slice(&plain_arena.staged());
            bare.encrypt_inout_detached(&nonce, &[], InOutBuf::from(&mut held[..FRAMES]))
                .is_ok()
        },
    ));
    reports.push(compare(
        "bisect seal: seal_next",
        0x4846,
        samples,
        plain_by_class,
        |slot| plain_arena.stage(*slot),
        |_| {
            let mut held = work.borrow_mut();
            held[..FRAMES].copy_from_slice(&plain_arena.staged());
            key.seal_next(black_box(&mut held[..]), FRAMES).is_ok()
        },
    ));
    reports
}

#[test]
fn h7_no_failed_open_releases_plaintext_or_moves_state() {
    let key = key();
    let good = sealed(&key, &[0x66; FRAMES], 5);
    let state = (key.next_seq(), key.sealed_bytes(), key.window());
    let at = tag_at(&good);
    let mut cases: Vec<Vec<u8>> = (at..good.len())
        .map(|byte| {
            let mut bad = good.clone();
            bad[byte] ^= 0x80;
            bad
        })
        .collect();
    let mut flipped = good.clone();
    flipped[HEADER_LEN + FRAMES / 2] ^= 1;
    cases.push(flipped);
    for bad in &cases {
        let mut out = vec![0xEE_u8; MAX_PLAINTEXT];
        assert_eq!(key.open_into(bad, &mut out), Err(EncRejection::Tag));
        assert!(
            out[..FRAMES].iter().all(|byte| *byte == 0),
            "no plaintext released"
        );
        assert_eq!((key.next_seq(), key.sealed_bytes(), key.window()), state);
    }
    let mut out = vec![0_u8; MAX_PLAINTEXT];
    assert!(
        key.open_into(&good, &mut out).is_ok(),
        "the genuine one opens"
    );
}

#[test]
fn h7_the_crates_take_the_accelerated_backends_where_expected() {
    let backends = expect_accelerated();
    assert!(!backends.line.is_empty());
}

#[test]
fn h7_every_comparison_gives_each_class_its_result() {
    for report in bisect(50) {
        assert_eq!(report.t.len(), timing::CROPS + 1, "{}", report.name);
    }
    for report in [
        first_against_last(50),
        fixed_against_random_tag(50),
        open_fixed_against_random(50),
        seal_fixed_against_random(50),
        valid_against_invalid(50),
    ] {
        assert_eq!(report.t.len(), timing::CROPS + 1, "{}", report.name);
    }
}

#[test]
#[ignore = "statistical timing test: run on an idle host, see the module documentation"]
fn h7_tag_comparison_timing() {
    print_backends();
    let samples = timing::samples();
    valid_against_invalid(samples).print();
    for report in [
        first_against_last(samples),
        fixed_against_random_tag(samples),
    ] {
        report.assert_constant_time();
    }
}

#[test]
#[ignore = "statistical timing test: run on an idle host, see the module documentation"]
fn h7_backend_timing() {
    print_backends();
    let samples = timing::samples();
    for report in [
        open_fixed_against_random(samples),
        seal_fixed_against_random(samples),
    ] {
        report.assert_constant_time();
    }
}

#[test]
#[ignore = "statistical timing test: run on an idle host, see the module documentation"]
fn h7_bisect_plaintext_timing() {
    print_backends();
    let reports = bisect(timing::samples());
    for report in &reports {
        report.print();
    }
    // The control of the run: the precheck reads header fields only, the
    // same for both classes, so a signal there is the harness's own and
    // voids every other step of the same run.
    reports[0].assert_constant_time();
}
