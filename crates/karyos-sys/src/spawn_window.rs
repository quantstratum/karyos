// SPDX-License-Identifier: Apache-2.0

//! Non-blocking locks a spawned child holds for a moment (karyos#1067).
//!
//! A `flock` belongs to an open file description, not to a process. A
//! child process that any thread of this process spawns shares every open
//! file description of this process from its fork until its exec, when
//! `O_CLOEXEC` closes them. For that window, a lock this process released
//! by closing its descriptor still looks held. On a loaded host about two
//! thirds of reopens raced against a loop of spawns were refused that way
//! (karyos#1067). The window ends with the child's exec, so a refusal that
//! outlasts [`LOCK_SPAWN_WINDOW`] is another holder's, and only that is
//! reported as held. What a lock excludes is unchanged; only how long a
//! refusal takes.

use core::time::Duration;

/// How long a non-blocking lock is tried again while it is held, so that a
/// spawned child's fork-to-exec window never reads as another holder.
pub const LOCK_SPAWN_WINDOW: Duration = Duration::from_secs(1);

/// The first pause between two tries.
const BACKOFF_FIRST: Duration = Duration::from_micros(100);

/// The longest pause between two tries.
const BACKOFF_MAX: Duration = Duration::from_millis(10);

/// Calls `try_lock` until it succeeds, fails otherwise, or has been
/// refused as held (`held` says which errors are) for [`LOCK_SPAWN_WINDOW`];
/// between tries it sleeps from 100 us, doubling up to 10 ms. Returns the
/// last outcome: a refusal as held only once the window has passed.
///
/// # Errors
///
/// `try_lock`'s last error: one `held` does not match at once, or a held
/// refusal that outlasted the window.
pub fn retry_held<T, E>(
    mut try_lock: impl FnMut() -> Result<T, E>,
    held: impl Fn(&E) -> bool,
) -> Result<T, E> {
    let start = std::time::Instant::now();
    let mut backoff = BACKOFF_FIRST;
    loop {
        match try_lock() {
            Err(error) if held(&error) => {
                let left = LOCK_SPAWN_WINDOW.saturating_sub(start.elapsed());
                if left.is_zero() {
                    return Err(error);
                }
                std::thread::sleep(backoff.min(left));
                backoff = backoff.saturating_mul(2).min(BACKOFF_MAX);
            }
            outcome => return outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "sleeps for the window")]
    fn a_refusal_that_clears_within_the_window_is_retried() {
        let mut tries = 0;
        let outcome: Result<u32, &str> = retry_held(
            || {
                tries += 1;
                if tries < 5 { Err("held") } else { Ok(tries) }
            },
            |error| *error == "held",
        );
        assert_eq!(outcome, Ok(5));
    }

    #[test]
    #[cfg_attr(miri, ignore = "sleeps for the window")]
    fn a_lasting_refusal_is_returned_after_the_window_and_not_much_later() {
        let start = std::time::Instant::now();
        let outcome: Result<(), &str> = retry_held(|| Err("held"), |error| *error == "held");
        let waited = start.elapsed();
        assert_eq!(outcome, Err("held"));
        assert!(waited >= LOCK_SPAWN_WINDOW, "{waited:?}");
        assert!(waited < LOCK_SPAWN_WINDOW * 10, "not bounded: {waited:?}");
    }

    #[test]
    fn another_error_is_returned_at_once() {
        let mut tries = 0;
        let outcome: Result<(), &str> = retry_held(
            || {
                tries += 1;
                Err("broken")
            },
            |error| *error == "held",
        );
        assert_eq!((outcome, tries), (Err("broken"), 1));
    }
}
