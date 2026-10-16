// SPDX-License-Identifier: Apache-2.0

//! Network sessions (`quantstratum-docs: karyos/design/network-sessions.md`,
//! S1 and S5; `driver-network-agents.md` §4.3, §4.4 and phase 4).
//!
//! [`receive`] is the receiver agent's session table: challenges, answers,
//! the installation chain with the conductor, retirement, quarantine and
//! timers. It is a state machine with no I/O: the caller passes decoded
//! controls, the binding key and the time, and sends what it returns.

pub mod paths;
pub mod rate;
pub mod receive;
pub mod send;

/// Where random challenge nonces come from (`karyos_sys::random` in the
/// driver, a counter in tests).
pub trait NonceSource {
    /// A fresh 128-bit nonce, not all zero; `None` when the source failed.
    fn nonce(&mut self) -> Option<[u64; 2]>;
}

/// Nonces from the operating system (`karyos_sys::random::fill_u64s`),
/// drawn on the control path.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsNonces;

impl NonceSource for OsNonces {
    fn nonce(&mut self) -> Option<[u64; 2]> {
        // An all-zero draw is retried once, then reported as a failure.
        for _ in 0..2 {
            let mut words = [0u64; 2];
            karyos_sys::random::fill_u64s(&mut words).ok()?;
            if words != [0, 0] {
                return Some(words);
            }
        }
        None
    }
}
