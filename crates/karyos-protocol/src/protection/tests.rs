// SPDX-License-Identifier: Apache-2.0

use super::*;
use karyos_sys::alloc_count::count;
use std::time::{Duration, Instant};

#[test]
fn trusted_adds_no_envelope_and_accepts_every_byte() {
    let mut datagram = [7_u8; 64];
    assert_eq!(Trusted.envelope_len(), 0);
    assert_eq!(Trusted.seal(&mut datagram, 40), Ok(40));
    assert_eq!(datagram, [7_u8; 64], "sealing writes nothing");
    assert_eq!(
        Trusted.open(datagram.get(..40).unwrap_or_default()),
        Verdict::Accept { frames: 40 }
    );
}

#[test]
fn a_buffer_too_small_is_refused() {
    let mut datagram = [0_u8; 16];
    assert_eq!(
        Trusted.seal(&mut datagram, 17),
        Err(SealError {
            needed: 17,
            available: 16
        })
    );
    let synthetic = Synthetic {
        spin_ns: 0,
        envelope: 8,
    };
    assert_eq!(
        synthetic.seal(&mut datagram, 9),
        Err(SealError {
            needed: 17,
            available: 16
        })
    );
    assert_eq!(
        synthetic.seal(&mut datagram, usize::MAX),
        Err(SealError {
            needed: usize::MAX,
            available: 16
        })
    );
}

#[test]
fn synthetic_round_trips_its_envelope() {
    let synthetic = Synthetic {
        spin_ns: 0,
        envelope: 16,
    };
    let mut datagram = [9_u8; 64];
    assert_eq!(synthetic.seal(&mut datagram, 32), Ok(48));
    assert_eq!(
        datagram.get(..32),
        Some(&[9_u8; 32][..]),
        "frames untouched"
    );
    assert_eq!(
        datagram.get(32..48),
        Some(&[0_u8; 16][..]),
        "envelope written"
    );
    assert_eq!(
        datagram.get(48..),
        Some(&[9_u8; 16][..]),
        "past the end untouched"
    );
    assert_eq!(
        synthetic.open(datagram.get(..48).unwrap_or_default()),
        Verdict::Accept { frames: 32 }
    );
    assert_eq!(
        synthetic.open(datagram.get(..15).unwrap_or_default()),
        Verdict::Reject(Rejection::Short)
    );
}

#[test]
fn synthetic_spins_at_least_its_time_on_each_side() {
    let synthetic = Synthetic {
        spin_ns: 200_000,
        envelope: 0,
    };
    let mut datagram = [0_u8; 8];
    let start = Instant::now();
    assert_eq!(synthetic.seal(&mut datagram, 8), Ok(8));
    assert!(start.elapsed() >= Duration::from_nanos(200_000));
    let start = Instant::now();
    assert_eq!(synthetic.open(&datagram), Verdict::Accept { frames: 8 });
    assert!(start.elapsed() >= Duration::from_nanos(200_000));
}

#[test]
fn neither_side_allocates() {
    let synthetic = Synthetic {
        spin_ns: 1_000,
        envelope: 16,
    };
    let mut datagram = [0_u8; 64];
    let (_, seen) = count(|| {
        let _ = Trusted.seal(&mut datagram, 32);
        let _ = Trusted.open(&datagram);
        let _ = synthetic.seal(&mut datagram, 32);
        let _ = synthetic.open(&datagram);
    });
    assert_eq!(seen, 0);
}
