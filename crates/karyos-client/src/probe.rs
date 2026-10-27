// SPDX-License-Identifier: Apache-2.0

//! A readiness probe of a driver in another process (Linux; R-CORE-35).
//!
//! [`probe`] connects to the driver's admission socket after the same
//! directory, socket and peer uid checks as a client, sends `ProbeHello`
//! without a descriptor and reads one `ProbeState`. It maps nothing, holds
//! no slot and closes the socket before returning: a probe touches no
//! shared memory and nothing on the data path.
//!
//! What the answer promises:
//!
//! - [`ProbeState::Ready`]: a client `Hello` now would be admitted, into no
//!   cutover. Route traffic.
//! - [`ProbeState::Starting`]: the host has not declared its startup
//!   complete, within its deadline. Wait.
//! - [`ProbeState::Recovering`]: admitting, but a stream still retains a
//!   predecessor mapping after a cutover. Do not route new traffic yet.
//! - [`ProbeState::NotReady`]: not admitting a client now, for the reason
//!   given; [`ProbeReason::Terminal`] does not end.
//! - [`ProbeState::Failed`]: startup missed its deadline; it does not end.
//!
//! Expected use, as an orchestrator's exec probe: every 5 s with a 1 s
//! timeout. Readiness passes on ready only. Liveness fails on failed, on
//! terminal, or after several unreachable answers in a row.

use std::path::Path;
use std::time::Duration;

use karyos_protocol::admission::{Message, VERSION, probe as wire, refusal};
use karyos_sys::error::SysError;
use karyos_sys::ipc;

use crate::ipc::{AttachError, receive, send};

/// A driver's readiness, as its admission socket answered a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProbeState {
    /// Startup not declared complete, within its deadline.
    Starting,
    /// A client would be admitted now, into no cutover.
    Ready,
    /// Admitting, but a cutover's predecessor mappings are still retained.
    Recovering,
    /// Not admitting a client now.
    NotReady(ProbeReason),
    /// Startup failed; it does not end.
    Failed(ProbeReason),
}

/// Why a driver is not ready, or why its startup failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProbeReason {
    /// An orderly shutdown: the driver stopped admitting.
    NotAdmitting,
    /// The driver holds its maximum of clients.
    Full,
    /// The driver is terminal.
    Terminal,
    /// The host did not declare its startup complete in time.
    StartupDeadline,
}

/// A probe's answer: the state and the driver's uptime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProbeAnswer {
    /// The driver's readiness.
    pub state: ProbeState,
    /// Nanoseconds since the driver started, on its clock.
    pub uptime_ns: u64,
}

/// Why a probe got no state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeError {
    /// No driver answers at the directory: no socket, a socket of another
    /// uid, or a refused connection.
    #[error("no driver reachable: {0}")]
    Unreachable(SysError),
    /// A driver answered, but it does not serve this probe: it runs another
    /// protocol version, or predates probes and closed the connection.
    #[error("the driver does not serve this probe (incompatible driver)")]
    Incompatible,
    /// The driver refused the probe with this code
    /// (`karyos_protocol::admission::refusal`), such as `LIMIT` when too
    /// many probes arrived at once.
    #[error("the driver refused the probe (code {code})")]
    Refused {
        /// The refusal code.
        code: u64,
    },
    /// The driver did not answer within the timeout.
    #[error("the driver did not answer in time")]
    Timeout,
}

/// Probes the driver whose admission socket is in `dir`, waiting at most
/// `timeout` for the connection and for the answer.
///
/// # Errors
///
/// [`ProbeError::Unreachable`] when nothing answers at `dir`;
/// [`ProbeError::Incompatible`] when the driver runs another protocol
/// version or closes the connection without an answer;
/// [`ProbeError::Refused`] and [`ProbeError::Timeout`].
pub fn probe(dir: &Path, timeout: Duration) -> Result<ProbeAnswer, ProbeError> {
    let socket = ipc::connect(dir, timeout).map_err(ProbeError::Unreachable)?;
    let failed = |error: AttachError| match error {
        AttachError::Timeout => ProbeError::Timeout,
        AttachError::Refused {
            code: refusal::INCOMPATIBLE_VERSION,
        }
        | AttachError::IncompatibleVersion { .. }
        | AttachError::Protocol => ProbeError::Incompatible,
        AttachError::Refused { code } => ProbeError::Refused { code },
        AttachError::Sys(error) => ProbeError::Unreachable(error),
        _ => ProbeError::Incompatible,
    };
    send(&socket, &Message::ProbeHello { version: VERSION }, None).map_err(failed)?;
    let (message, fd) = receive(&socket).map_err(failed)?;
    if fd.is_some() {
        return Err(ProbeError::Incompatible);
    }
    match message {
        Message::ProbeState {
            state,
            reason,
            uptime_ns,
        } => Ok(ProbeAnswer {
            state: state_of(state, reason).ok_or(ProbeError::Incompatible)?,
            uptime_ns,
        }),
        Message::Refused {
            code: refusal::INCOMPATIBLE_VERSION,
            ..
        } => Err(ProbeError::Incompatible),
        Message::Refused { code, .. } => Err(ProbeError::Refused { code }),
        _ => Err(ProbeError::Incompatible),
    }
}

/// The typed state of a decoded `ProbeState`, whose state and reason the
/// decoder already checked as consistent.
fn state_of(state: u64, reason: u64) -> Option<ProbeState> {
    let reason = match reason {
        wire::NONE => None,
        wire::NOT_ADMITTING => Some(ProbeReason::NotAdmitting),
        wire::FULL => Some(ProbeReason::Full),
        wire::TERMINAL => Some(ProbeReason::Terminal),
        wire::STARTUP_DEADLINE => Some(ProbeReason::StartupDeadline),
        _ => return None,
    };
    Some(match (state, reason) {
        (wire::STARTING, None) => ProbeState::Starting,
        (wire::READY, None) => ProbeState::Ready,
        (wire::RECOVERING, None) => ProbeState::Recovering,
        (wire::NOT_READY, Some(reason)) => ProbeState::NotReady(reason),
        (wire::FAILED, Some(reason)) => ProbeState::Failed(reason),
        _ => return None,
    })
}
