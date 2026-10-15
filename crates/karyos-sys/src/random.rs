// SPDX-License-Identifier: Apache-2.0

//! Random words for identities such as the driver's 128-bit `driver_id`
//! (SPEC.md §4), on the control path. Owner decision, 2026-10-15 (ACS
//! 11410): the operating system's random source through `rustix`
//! (`getrandom`) on Linux, and the standard library's per-process
//! `RandomState` keys elsewhere; no new dependency.

use crate::error::SysError;

/// Fills `words` with random values.
///
/// # Errors
///
/// Returns [`SysError::Os`] when the operating system's random source
/// fails (Linux).
pub fn fill_u64s(words: &mut [u64]) -> Result<(), SysError> {
    for word in words {
        *word = random_u64()?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn random_u64() -> Result<u64, SysError> {
    use rustix::io::Errno;
    use rustix::rand::{GetRandomFlags, getrandom};

    let mut bytes = [0u8; 8];
    let mut filled = 0;
    while filled < bytes.len() {
        let rest = bytes.get_mut(filled..).unwrap_or_default();
        match getrandom(rest, GetRandomFlags::empty()) {
            Ok(written) => filled += written,
            Err(Errno::INTR) => {}
            Err(errno) => {
                return Err(SysError::Os {
                    operation: "getrandom",
                    errno: errno.raw_os_error(),
                });
            }
        }
    }
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(not(target_os = "linux"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the same signature as the Linux source, which can fail"
)]
fn random_u64() -> Result<u64, SysError> {
    use std::hash::{BuildHasher, Hasher};

    // Each `RandomState` draws its keys from the standard library's
    // per-process random seed.
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(0);
    Ok(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_are_filled_with_distinct_values() {
        let mut words = [0u64; 16];
        fill_u64s(&mut words).unwrap();
        let mut sorted = words;
        sorted.sort_unstable();
        // Sixteen random words are distinct with overwhelming probability.
        assert!(sorted.windows(2).all(|pair| pair[0] != pair[1]));
        let mut again = [0u64; 16];
        fill_u64s(&mut again).unwrap();
        assert_ne!(words, again);
    }
}
