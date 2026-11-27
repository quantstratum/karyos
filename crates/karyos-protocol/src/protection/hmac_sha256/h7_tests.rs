// SPDX-License-Identifier: Apache-2.0

//! Gate H7, constant time, for the `authenticated` class
//! (`quantstratum-docs: karyos/design/wire-threat-model-manifest.md`
//! section 7; ADR-0086 "Hard gates"), on the shared harness
//! [`crate::protection::timing`].
//!
//! Review: [`HmacSha256::open_envelope`] reads only header fields, all
//! public, before the tag, and never branches on a tag byte. The tag is
//! compared by [`HmacState::verify_truncated_left`]: it ORs the XOR of
//! every byte pair into one accumulator over the whole tag, with no early
//! exit, and tests the accumulator once, behind `black_box`. Its only
//! branch is on the tag's length, which is public (a wrong `tag_len` is
//! refused before it). The MAC itself is SHA-256 over the keyed states,
//! with no secret-dependent branch or index (`sha2` 0.11.1, soft and
//! SHA-NI backends).
//!
//! The statistical tests are `#[ignore]`d. Gated (`|t|` below 4.5): an
//! invalid tag differing in its first against its last byte, and a fixed
//! against a random invalid tag, both through the envelope open and
//! through the bare truncated comparison; a valid open of fixed against
//! random frames; a seal of fixed against random frames. Measured and not
//! gated: a valid against an invalid tag (whether a datagram was accepted
//! is observable anyway). A run counts as H7 evidence only if, in that
//! same run, the harness's A/A control
//! (`timing::tests::h7_identical_classes_give_no_signal`) is below 4.5.
//!
//! Command, on an otherwise idle host (`KARYOS_H7_SAMPLES` sets the samples
//! per class, default 1 000 000):
//! `cargo test -p karyos-protocol --release --lib -- --ignored h7_ --nocapture --test-threads=1`

#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

use std::cell::RefCell;
use std::hint::black_box;

use super::*;
use crate::protection::timing::{self, Class, Report, Rng, compare};

/// Inner frame bytes of every measured datagram: a typical batch.
const FRAMES: usize = 1024;

/// The length of a sealed datagram of [`FRAMES`].
const SEALED: usize = FRAMES + HEADER_LEN + TAG_LEN;

const BINDING: Binding = Binding {
    domain: Domain::Data,
    party_epoch: 0,
    session_id: 9,
    stream_id: 6,
    key_id: 3,
};

fn key() -> HmacSha256 {
    HmacSha256::new(&[0x5A; 32], BINDING, 0).unwrap()
}

fn sealed(key: &HmacSha256, frames: &[u8], seq: u64) -> Vec<u8> {
    let mut datagram = vec![0_u8; SEALED];
    datagram[..frames.len()].copy_from_slice(frames);
    let total = key.seal_with(&mut datagram, frames.len(), seq).unwrap();
    datagram.truncate(total);
    datagram
}

/// Every input of a comparison in one preallocated array of
/// [`timing::SLOTS`] slots of one stride, cache-line aligned, both classes
/// alike.
struct Arena {
    bytes: RefCell<Vec<u8>>,
    base: usize,
    len: usize,
    stride: usize,
    next: std::cell::Cell<usize>,
}

const LINE: usize = 128;

impl Arena {
    fn new(len: usize) -> Self {
        let stride = len.div_ceil(LINE) * LINE;
        let bytes = vec![0_u8; stride * timing::SLOTS + LINE];
        let base = bytes.as_ptr().align_offset(LINE);
        Self {
            bytes: RefCell::new(bytes),
            base,
            len,
            stride,
            next: std::cell::Cell::new(0),
        }
    }

    fn push(&self, value: &[u8]) -> usize {
        assert_eq!(value.len(), self.len);
        let at = self.next.get();
        self.next.set(at + 1);
        let start = self.base + at * self.stride;
        self.bytes.borrow_mut()[start..start + self.len].copy_from_slice(value);
        at
    }

    fn slot(&self, at: usize) -> std::cell::Ref<'_, [u8]> {
        let start = self.base + at * self.stride;
        std::cell::Ref::map(self.bytes.borrow(), |bytes| &bytes[start..start + self.len])
    }
}

fn refused_by_tag(key: &HmacSha256, datagram: &[u8]) -> bool {
    key.open_envelope(black_box(datagram)) == Err(Rejection::Tag)
}

fn open_first_against_last(samples: usize) -> Report {
    let key = key();
    let good = sealed(&key, &[0x11; FRAMES], 1);
    let at = SEALED - TAG_LEN;
    let arena = Arena::new(SEALED);
    compare(
        "envelope open, invalid tag, first byte against last byte",
        0x4851,
        samples,
        |class, _| {
            let mut bad = good.clone();
            match class {
                Class::A => bad[at] ^= 1,
                Class::B => bad[at + TAG_LEN - 1] ^= 1,
            }
            arena.push(&bad)
        },
        |_| {},
        |slot| refused_by_tag(&key, &arena.slot(*slot)),
    )
}

fn open_fixed_against_random_tag(samples: usize) -> Report {
    let key = key();
    let good = sealed(&key, &[0x22; FRAMES], 1);
    let at = SEALED - TAG_LEN;
    let arena = Arena::new(SEALED);
    compare(
        "envelope open, invalid tag, fixed against random",
        0x4852,
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
        |_| {},
        |slot| refused_by_tag(&key, &arena.slot(*slot)),
    )
}

/// The bare truncated comparison: the MAC of one fixed message, compared
/// with a tag of each class.
fn truncated(name: &str, seed: u64, samples: usize, fixed: bool) -> Report {
    let mac = HmacKey::new(&[0x5A; 32]);
    let message = [0x33_u8; 64];
    let full = {
        let mut state = mac.mac();
        state.update(&message);
        state.finalize()
    };
    let arena = Arena::new(TAG_LEN);
    compare(
        name,
        seed,
        samples,
        |class, rng: &mut Rng| {
            let mut tag: [u8; TAG_LEN] = full[..TAG_LEN].try_into().unwrap();
            match (fixed, class) {
                (false, Class::A) => tag[0] ^= 1,
                (false, Class::B) => tag[TAG_LEN - 1] ^= 1,
                (true, Class::A) => tag[0] ^= 0x5A,
                (true, Class::B) => {
                    while tag[..] == full[..TAG_LEN] {
                        rng.fill(&mut tag);
                    }
                }
            }
            arena.push(&tag)
        },
        |_| {},
        |slot| {
            let mut state = mac.mac();
            state.update(black_box(&message));
            !state.verify_truncated_left(black_box(&arena.slot(*slot)))
        },
    )
}

fn open_fixed_against_random(samples: usize) -> Report {
    let key = key();
    let arena = Arena::new(SEALED);
    let mut seq = 1_u64;
    compare(
        "valid open, fixed against random frames",
        0x4855,
        samples,
        |class, rng| {
            let mut frames = [0x44_u8; FRAMES];
            if class == Class::B {
                rng.fill(&mut frames);
            }
            seq += 1;
            arena.push(&sealed(&key, &frames, seq))
        },
        |_| {},
        |slot| key.open_envelope(black_box(&arena.slot(*slot))).is_ok(),
    )
}

fn seal_fixed_against_random(samples: usize) -> Report {
    let key = key();
    let arena = Arena::new(FRAMES);
    let work = RefCell::new(vec![0_u8; SEALED]);
    compare(
        "seal, fixed against random frames",
        0x4856,
        samples,
        |class, rng| {
            let mut frames = [0x55_u8; FRAMES];
            if class == Class::B {
                rng.fill(&mut frames);
            }
            arena.push(&frames)
        },
        |_| {},
        |slot| {
            let mut held = work.borrow_mut();
            held[..FRAMES].copy_from_slice(&arena.slot(*slot));
            key.seal_with(black_box(&mut held[..]), FRAMES, 1).is_ok()
        },
    )
}

fn valid_against_invalid(samples: usize) -> Report {
    let key = key();
    let good = sealed(&key, &[0x66; FRAMES], 1);
    let at = SEALED - TAG_LEN;
    let arena = Arena::new(SEALED);
    compare(
        "valid tag against invalid tag",
        0x4857,
        samples,
        |class, _| {
            let mut datagram = good.clone();
            if class == Class::B {
                datagram[at + TAG_LEN / 2] ^= 1;
            }
            (class, arena.push(&datagram))
        },
        |_| {},
        |(class, slot)| {
            let datagram = arena.slot(*slot);
            match class {
                Class::A => key.open_envelope(black_box(&datagram)).is_ok(),
                Class::B => refused_by_tag(&key, &datagram),
            }
        },
    )
}

fn gated(samples: usize) -> [Report; 6] {
    [
        open_first_against_last(samples),
        open_fixed_against_random_tag(samples),
        truncated(
            "truncated compare, first byte against last byte",
            0x4853,
            samples,
            false,
        ),
        truncated(
            "truncated compare, fixed against random",
            0x4854,
            samples,
            true,
        ),
        open_fixed_against_random(samples),
        seal_fixed_against_random(samples),
    ]
}

#[test]
fn h7_every_comparison_gives_each_class_its_result() {
    for report in gated(50) {
        assert_eq!(report.t.len(), timing::CROPS + 1, "{}", report.name);
    }
    assert_eq!(valid_against_invalid(50).t.len(), timing::CROPS + 1);
}

#[test]
fn h7_a_failed_open_moves_no_state() {
    let key = key();
    let good = sealed(&key, &[0x77; FRAMES], 5);
    let next = key.next_seq();
    for byte in SEALED - TAG_LEN..SEALED {
        let mut bad = good.clone();
        bad[byte] ^= 0x80;
        assert_eq!(key.open_envelope(&bad), Err(Rejection::Tag));
        assert_eq!(key.next_seq(), next);
    }
    assert!(key.open_envelope(&good).is_ok());
}

#[test]
#[ignore = "statistical timing test: run on an idle host, see the module documentation"]
fn h7_hmac_tag_comparison_timing() {
    let samples = timing::samples();
    valid_against_invalid(samples).print();
    for report in gated(samples) {
        report.assert_constant_time();
    }
}
