// SPDX-License-Identifier: Apache-2.0

//! Unwinding stops at the boundary (SPEC.md §10.2): every exported function
//! runs its body through [`guard`], so a panic returns
//! [`Status::Internal`] instead of unwinding into the caller. A handle held
//! while the panic unwound is poisoned by its table (`handles`).

use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::status::Status;

/// Runs `body`, catching a panic as [`Status::Internal`], and returns the
/// status code.
pub(crate) fn guard(body: impl FnOnce() -> Status) -> i32 {
    // Unwind safety: an object a panic left inconsistent is reachable only
    // through its handle, whose slot the panic poisoned.
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(status) => status.code(),
        Err(payload) => {
            drop_payload(payload);
            Status::Internal.code()
        }
    }
}

/// How many times a payload whose drop panics is replaced by that panic's
/// payload before the last one is forgotten.
const MAX_PAYLOAD_DROPS: usize = 4;

/// Drops a panic's payload without letting a panicking `Drop` unwind out
/// of an `extern "C"` function (which aborts the process): each drop runs
/// under `catch_unwind`, a panic in it gives the next payload to drop, and
/// after [`MAX_PAYLOAD_DROPS`] such panics the last payload is forgotten
/// (it leaks; only a payload whose drops keep panicking gets there).
pub(crate) fn drop_payload(mut payload: Box<dyn core::any::Any + Send>) {
    for _ in 0..MAX_PAYLOAD_DROPS {
        match catch_unwind(AssertUnwindSafe(move || drop(payload))) {
            Ok(()) => return,
            Err(next) => payload = next,
        }
    }
    core::mem::forget(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_in_the_body_returns_internal() {
        assert_eq!(guard(|| Status::Busy), Status::Busy.code());
        assert_eq!(
            guard(|| std::panic::resume_unwind(Box::new("in a call"))),
            Status::Internal.code()
        );
        // A payload whose drop panics is never dropped.
        struct PanicsOnDrop;
        impl Drop for PanicsOnDrop {
            fn drop(&mut self) {
                std::panic::resume_unwind(Box::new("in drop"));
            }
        }
        assert_eq!(
            guard(|| std::panic::resume_unwind(Box::new(PanicsOnDrop))),
            Status::Internal.code()
        );
    }

    /// A payload whose every drop panics is given up after a bounded
    /// number of drops: the call still returns. Its last payload leaks by
    /// design, which Miri reports, so Miri skips this test.
    #[test]
    #[cfg_attr(miri, ignore = "the last payload is forgotten on purpose")]
    fn a_payload_that_always_panics_on_drop_is_given_up() {
        struct AlwaysPanics;
        impl Drop for AlwaysPanics {
            fn drop(&mut self) {
                std::panic::resume_unwind(Box::new(AlwaysPanics));
            }
        }
        assert_eq!(
            guard(|| std::panic::resume_unwind(Box::new(AlwaysPanics))),
            Status::Internal.code()
        );
    }
}
