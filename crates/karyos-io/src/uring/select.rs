// SPDX-License-Identifier: Apache-2.0

//! Backend selection with an explicit `io_uring_or_sockets` fallback
//! (`quantstratum-docs: karyos/design/io-uring-backend.md` 4.3, choice
//! IU-7; owner item 2: "explicit `io_uring_or_sockets` fallback,
//! capability reporting").
//!
//! The contract forbids silent substitution. With
//! [`UringChoice::IoUring`] a failed `io_uring` open is the open's error,
//! nothing falls back and nothing stays open. With
//! [`UringChoice::IoUringOrSockets`] the same failure opens the sockets
//! backend instead, and the selection says so: [`Selected::Sockets`]
//! carries the reason as `uring_ring = Fallback(reason)`, and
//! [`capability_fallbacks`] counts it. A failure of the sockets open is
//! never hidden either.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};

use crate::backend::{Capability, CapabilityState, OpenError, Reason};

/// Fallbacks from `io_uring` to sockets over the process
/// (`capability_fallback`, design 4.3).
static CAPABILITY_FALLBACKS: AtomicU64 = AtomicU64::new(0);

/// Fallbacks from `io_uring` to sockets taken so far by this process.
#[must_use]
pub fn capability_fallbacks() -> u64 {
    CAPABILITY_FALLBACKS.load(Ordering::Relaxed)
}

/// The configured backend of an `io_uring` capable selection (SPEC.md
/// §16.9 `[io] backend`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UringChoice {
    /// `io_uring`, required: a failed probe fails the open.
    IoUring,
    /// `io_uring_or_sockets`: a failed probe opens sockets, with a warning
    /// and a counter.
    IoUringOrSockets,
}

impl UringChoice {
    /// Parses the `[io] backend` value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "io_uring" => Some(Self::IoUring),
            "io_uring_or_sockets" => Some(Self::IoUringOrSockets),
            _ => None,
        }
    }
}

/// The backend a selection opened.
#[derive(Debug)]
pub enum Selected<U, S> {
    /// The `io_uring` backend; `uring_ring = Active`.
    Uring(U),
    /// The sockets backend, after `io_uring` failed.
    Sockets {
        /// The sockets backend.
        sockets: S,
        /// `uring_ring = Fallback(reason)`.
        uring_ring: CapabilityState,
        /// The `io_uring` open's error, for the warning.
        cause: OpenError,
    },
}

impl<U, S> Selected<U, S> {
    /// The `uring_ring` capability state of the selection.
    #[must_use]
    pub fn uring_ring(&self) -> CapabilityState {
        match self {
            Self::Uring(_) => CapabilityState::Active,
            Self::Sockets { uring_ring, .. } => *uring_ring,
        }
    }
}

/// The reason a failed `io_uring` open gives its fallback: `EPERM` and
/// `EACCES` are denials, `ENOSYS` is unsupported (never published as
/// absence), anything else a failed probe.
#[must_use]
pub fn reason_of(error: OpenError) -> Reason {
    match error {
        OpenError::Os {
            errno: errno @ (1 | 13),
            ..
        } => Reason::Denied { errno },
        OpenError::Os { errno: 38, .. } => Reason::Unsupported { errno: 38 },
        OpenError::Os { errno, .. } => Reason::ProbeFailed { errno },
        _ => Reason::ProbeFailed { errno: 0 },
    }
}

/// Whether `error` is a failed `io_uring` probe (design 4.1): a setup,
/// feature, opcode, registration or cancel probe the kernel or a seccomp
/// profile refused. Configuration errors, socket errors and the rest are
/// not, and never fall back.
#[must_use]
pub fn is_probe_failure(error: OpenError) -> bool {
    matches!(error, OpenError::Os { operation, .. } if operation.starts_with("io_uring_"))
}

/// Opens `io_uring` through `uring` on the initial open; on a failed
/// required probe, falls back to `sockets` only when `choice` allows it
/// (design 4.3). Optional facilities (SQPOLL, fixed files) fall back
/// inside the backend and never reach here; a `reopen` that loses a
/// required capability fails instead, as the design asks.
///
/// # Errors
///
/// With [`UringChoice::IoUring`], a failed required probe is
/// [`OpenError::RequiredCapability`] naming [`Capability::UringRing`] and
/// its reason. Any other error of `uring` is returned as it is under
/// either choice: it is not a capability the fallback can replace. With
/// [`UringChoice::IoUringOrSockets`], the error of `sockets` when that
/// fails too.
pub fn select<U, S>(
    choice: UringChoice,
    uring: impl FnOnce() -> Result<U, OpenError>,
    sockets: impl FnOnce() -> Result<S, OpenError>,
) -> Result<Selected<U, S>, OpenError> {
    let error = match uring() {
        Ok(opened) => return Ok(Selected::Uring(opened)),
        Err(error) => error,
    };
    if !is_probe_failure(error) {
        return Err(error);
    }
    let state = CapabilityState::Unavailable(reason_of(error));
    match choice {
        UringChoice::IoUring => Err(OpenError::RequiredCapability {
            capability: Capability::UringRing,
            state,
        }),
        UringChoice::IoUringOrSockets => {
            let sockets = sockets()?;
            CAPABILITY_FALLBACKS.fetch_add(1, Ordering::Relaxed);
            Ok(Selected::Sockets {
                sockets,
                uring_ring: CapabilityState::Fallback(reason_of(error)),
                cause: error,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DENIED: OpenError = OpenError::Os {
        operation: "io_uring_setup",
        errno: 1,
    };

    #[test]
    fn a_required_io_uring_fails_instead_of_falling_back() {
        let mut sockets_opened = false;
        let selected = select(
            UringChoice::IoUring,
            || Err::<(), _>(DENIED),
            || {
                sockets_opened = true;
                Ok(())
            },
        );
        assert_eq!(
            selected.err(),
            Some(OpenError::RequiredCapability {
                capability: Capability::UringRing,
                state: CapabilityState::Unavailable(Reason::Denied { errno: 1 })
            })
        );
        assert!(!sockets_opened, "nothing falls back silently");
    }

    #[test]
    fn io_uring_or_sockets_falls_back_explicitly_and_counts_it() {
        let before = capability_fallbacks();
        let selected = select(
            UringChoice::IoUringOrSockets,
            || Err::<(), _>(DENIED),
            || Ok("sockets"),
        );
        let Ok(selected) = selected else {
            panic!("fallback refused: {selected:?}");
        };
        assert_eq!(
            selected.uring_ring(),
            CapabilityState::Fallback(Reason::Denied { errno: 1 })
        );
        assert!(matches!(
            selected,
            Selected::Sockets {
                sockets: "sockets",
                cause: DENIED,
                ..
            }
        ));
        assert!(capability_fallbacks() > before);
    }

    #[test]
    fn a_working_io_uring_is_selected_either_way() {
        for choice in [UringChoice::IoUring, UringChoice::IoUringOrSockets] {
            let selected = select(choice, || Ok::<_, OpenError>("uring"), || Ok("sockets"));
            assert!(matches!(selected, Ok(Selected::Uring("uring"))));
        }
    }

    #[test]
    fn a_failed_sockets_fallback_is_not_hidden() {
        let failed = OpenError::Os {
            operation: "socket",
            errno: 24,
        };
        let selected = select(
            UringChoice::IoUringOrSockets,
            || Err::<(), _>(DENIED),
            || Err::<(), _>(failed),
        );
        assert_eq!(selected.err(), Some(failed));
    }

    #[test]
    fn only_a_failed_probe_falls_back() {
        for not_a_probe in [
            OpenError::InvalidConfig {
                field: "tx_slots",
                value: 0,
            },
            OpenError::Os {
                operation: "bind",
                errno: 98,
            },
        ] {
            for choice in [UringChoice::IoUring, UringChoice::IoUringOrSockets] {
                let selected = select(choice, || Err::<(), _>(not_a_probe), || Ok("sockets"));
                assert_eq!(selected.err(), Some(not_a_probe), "{choice:?}");
            }
        }
    }

    #[test]
    fn reasons_keep_unsupported_and_denied_apart() {
        assert_eq!(
            reason_of(OpenError::Os {
                operation: "io_uring_setup",
                errno: 38
            }),
            Reason::Unsupported { errno: 38 }
        );
        assert_eq!(reason_of(DENIED), Reason::Denied { errno: 1 });
        assert_eq!(
            UringChoice::parse("io_uring_or_sockets"),
            Some(UringChoice::IoUringOrSockets)
        );
        assert_eq!(UringChoice::parse("sockets"), None);
    }
}
