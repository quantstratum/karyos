// SPDX-License-Identifier: Apache-2.0

//! Backend selection with an explicit `af_xdp_or_sockets` fallback
//! (`quantstratum-docs: karyos/design/af-xdp-backend.md` 4.3, "an
//! `af_xdp_or_sockets` mode would follow IU-7"; karyos#643), the same
//! policy as `io_uring_or_sockets`.
//!
//! With [`XdpChoice::AfXdp`] a failed required AF_XDP step (the socket,
//! the UMEM registration, the rings, the bind, the program load or the
//! attach) is [`OpenError::RequiredCapability`] naming
//! [`Capability::XdpSocket`]; nothing falls back. With
//! [`XdpChoice::AfXdpOrSockets`] the same failure, on the initial open
//! only, opens sockets instead and says so. Any other error, a
//! configuration error above all, fails under either choice.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};

use crate::backend::{Capability, CapabilityState, OpenError, Reason};

static CAPABILITY_FALLBACKS: AtomicU64 = AtomicU64::new(0);

/// Fallbacks from AF_XDP to sockets taken by this process.
#[must_use]
pub fn capability_fallbacks() -> u64 {
    CAPABILITY_FALLBACKS.load(Ordering::Relaxed)
}

/// The configured backend of an AF_XDP capable selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpChoice {
    /// `af_xdp`, required.
    AfXdp,
    /// `af_xdp_or_sockets`: a failed required step opens sockets.
    AfXdpOrSockets,
}

impl XdpChoice {
    /// Parses the `[io] backend` value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "af_xdp" => Some(Self::AfXdp),
            "af_xdp_or_sockets" => Some(Self::AfXdpOrSockets),
            _ => None,
        }
    }
}

/// The backend a selection opened.
#[derive(Debug)]
pub enum Selected<X, S> {
    /// AF_XDP; `xdp_socket = Active`.
    Xdp(X),
    /// Sockets, after a required AF_XDP step failed.
    Sockets {
        /// The sockets backend.
        sockets: S,
        /// `xdp_socket = Fallback(reason)`.
        xdp_socket: CapabilityState,
        /// The AF_XDP open's error, for the warning.
        cause: OpenError,
    },
}

/// Whether `error` is a failed required AF_XDP step: an `OpenError::Os`
/// whose operation is one of the backend's (`xsk_*`, `xdp_*`).
#[must_use]
pub fn is_required_step_failure(error: OpenError) -> bool {
    matches!(error, OpenError::Os { operation, .. }
        if operation.starts_with("xsk_") || operation.starts_with("xdp_"))
}

fn reason_of(error: OpenError) -> Reason {
    match error {
        OpenError::Os {
            errno: errno @ (1 | 13),
            ..
        } => Reason::Denied { errno },
        OpenError::Os {
            errno: errno @ (38 | 97),
            ..
        } => Reason::Unsupported { errno },
        OpenError::Os { errno, .. } => Reason::ProbeFailed { errno },
        _ => Reason::ProbeFailed { errno: 0 },
    }
}

/// Opens AF_XDP through `xdp` on the initial open; on a failed required
/// step falls back to `sockets` only under [`XdpChoice::AfXdpOrSockets`].
///
/// # Errors
///
/// [`OpenError::RequiredCapability`] for a failed required step under
/// [`XdpChoice::AfXdp`]; any other error of `xdp` as it is; the error of
/// `sockets` when the fallback fails too.
pub fn select<X, S>(
    choice: XdpChoice,
    xdp: impl FnOnce() -> Result<X, OpenError>,
    sockets: impl FnOnce() -> Result<S, OpenError>,
) -> Result<Selected<X, S>, OpenError> {
    let error = match xdp() {
        Ok(opened) => return Ok(Selected::Xdp(opened)),
        Err(error) => error,
    };
    if !is_required_step_failure(error) {
        return Err(error);
    }
    match choice {
        XdpChoice::AfXdp => Err(OpenError::RequiredCapability {
            capability: Capability::XdpSocket,
            state: CapabilityState::Unavailable(reason_of(error)),
        }),
        XdpChoice::AfXdpOrSockets => {
            let sockets = sockets()?;
            CAPABILITY_FALLBACKS.fetch_add(1, Ordering::Relaxed);
            Ok(Selected::Sockets {
                sockets,
                xdp_socket: CapabilityState::Fallback(reason_of(error)),
                cause: error,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DENIED: OpenError = OpenError::Os {
        operation: "xsk_socket",
        errno: 1,
    };

    #[test]
    fn a_required_af_xdp_fails_with_its_capability_and_never_falls_back() {
        let mut opened = false;
        let selected = select(
            XdpChoice::AfXdp,
            || Err::<(), _>(DENIED),
            || {
                opened = true;
                Ok(())
            },
        );
        assert_eq!(
            selected.err(),
            Some(OpenError::RequiredCapability {
                capability: Capability::XdpSocket,
                state: CapabilityState::Unavailable(Reason::Denied { errno: 1 })
            })
        );
        assert!(!opened);
    }

    #[test]
    fn af_xdp_or_sockets_falls_back_explicitly_and_counts_it() {
        let before = capability_fallbacks();
        let selected = select(
            XdpChoice::AfXdpOrSockets,
            || Err::<(), _>(DENIED),
            || Ok("sockets"),
        );
        assert!(matches!(
            selected,
            Ok(Selected::Sockets {
                sockets: "sockets",
                xdp_socket: CapabilityState::Fallback(Reason::Denied { errno: 1 }),
                cause: DENIED
            })
        ));
        assert!(capability_fallbacks() > before);
    }

    #[test]
    fn only_a_failed_required_step_falls_back() {
        let config = OpenError::InvalidConfig {
            field: "max_datagram",
            value: 9000,
        };
        for choice in [XdpChoice::AfXdp, XdpChoice::AfXdpOrSockets] {
            assert_eq!(
                select(choice, || Err::<(), _>(config), || Ok(())).err(),
                Some(config)
            );
        }
        assert_eq!(
            XdpChoice::parse("af_xdp_or_sockets"),
            Some(XdpChoice::AfXdpOrSockets)
        );
    }
}
