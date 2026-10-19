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
            forget_payload(payload);
            Status::Internal.code()
        }
    }
}

/// Forgets a panic's payload: dropping it could panic in turn (a payload
/// whose `Drop` panics), and that unwind would leave an `extern "C"`
/// function and abort the process. The payload leaks; a panic is already
/// a poisoned handle.
pub(crate) fn forget_payload(payload: Box<dyn core::any::Any + Send>) {
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
}
