// SPDX-License-Identifier: Apache-2.0

//! The relay to the agent's local socket (karyos#708): one request per
//! connection, as every API v1 client makes it, with the `relay
//! PRINCIPAL` prefix the agent reads for a relay's uid. The line carries
//! the principal and the request, never a role: the agent gives the
//! principal its role from its own table.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

/// The first word of every agent request.
pub const PROTOCOL: &str = "KARYOS-AGENT";
/// The API version relayed.
pub const API_VERSION: u32 = 1;
/// The longest request relayed, in bytes: the agent's longest request
/// (`MAX_JOIN_REQUEST` of `karyos-agent`'s server), which bounds every
/// request without its relay prefix.
pub const MAX_REQUEST: usize = 1024;
/// The longest principal name, in bytes (the agent's `MAX_PRINCIPAL`).
pub const MAX_PRINCIPAL: usize = 64;
/// The longest agent answer relayed, in bytes; a longer one is refused.
pub const MAX_REPLY: usize = 8 << 20;
/// The time the agent has to answer in all: its own read and write
/// deadlines are 250 ms each, so this is a bound on a stuck agent only.
pub const AGENT_DEADLINE: Duration = Duration::from_secs(2);
/// The longest one read of the answer waits.
const READ_STEP: Duration = Duration::from_millis(100);

/// Why a request was not relayed, or its answer not had.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RelayError {
    /// The principal's name is not one the agent takes.
    #[error("not a principal name")]
    Principal,
    /// The request is empty, too long, holds a control character or is a
    /// relay itself.
    #[error("not a request")]
    Request,
    /// The agent's answer was longer than [`MAX_REPLY`], incomplete, or
    /// not had within [`AGENT_DEADLINE`].
    #[error("no complete answer from the agent")]
    Answer,
    /// The agent's socket could not be used.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Whether `name` is a principal name the agent takes: 1 to
/// [`MAX_PRINCIPAL`] bytes of ASCII letters, digits, `.`, `_`, `-`, `@`
/// and `:` (the agent's `valid_principal`).
#[must_use]
pub fn valid_principal(name: &str) -> bool {
    (1..=MAX_PRINCIPAL).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-@:".contains(&byte))
}

/// The agent line relaying `request` for `principal`, with its newline.
///
/// # Errors
///
/// [`RelayError::Principal`] or [`RelayError::Request`].
pub fn line(principal: &str, request: &str) -> Result<String, RelayError> {
    if !valid_principal(principal) {
        return Err(RelayError::Principal);
    }
    let first = request.split(' ').next().unwrap_or("");
    if request.is_empty()
        || request.len() > MAX_REQUEST
        || request.chars().any(char::is_control)
        || first.is_empty()
        || first == "relay"
    {
        return Err(RelayError::Request);
    }
    Ok(format!(
        "{PROTOCOL} {API_VERSION} relay {principal} {request}\n"
    ))
}

/// Sends `line` to the agent's socket at `socket` and returns its answer,
/// one JSON object and its newline.
///
/// # Errors
///
/// [`RelayError::Io`] when the socket cannot be used, and
/// [`RelayError::Answer`] for an answer too long, cut short or late.
pub fn relay(socket: &Path, line: &str) -> Result<Vec<u8>, RelayError> {
    let start = Instant::now();
    let mut stream = UnixStream::connect(socket)?;
    // Set once, before the exchange: macOS refuses the option on a socket
    // whose peer has closed. Each read waits READ_STEP at most, and the
    // deadline is checked between reads.
    stream.set_write_timeout(Some(AGENT_DEADLINE))?;
    stream.set_read_timeout(Some(READ_STEP))?;
    stream.write_all(line.as_bytes())?;
    let mut answer = Vec::new();
    let mut buffer = [0u8; 64 << 10];
    loop {
        let left = AGENT_DEADLINE.saturating_sub(start.elapsed());
        if left.is_zero() {
            return Err(RelayError::Answer);
        }
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                answer.extend_from_slice(buffer.get(..read).ok_or(RelayError::Answer)?);
                if answer.len() > MAX_REPLY {
                    return Err(RelayError::Answer);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    // An answer without its newline was cut short by the agent.
    if answer.last() != Some(&b'\n') {
        return Err(RelayError::Answer);
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    /// A line names the principal and the request, nothing else; a
    /// request that would change the line's shape is refused.
    #[test]
    fn a_line_carries_the_principal_and_the_request_only() {
        assert_eq!(
            line("svc.ops", "guard-close /d 3 drill").unwrap(),
            "KARYOS-AGENT 1 relay svc.ops guard-close /d 3 drill\n"
        );
        for principal in ["", "a b", "a\nb", "svc/ops", &"a".repeat(MAX_PRINCIPAL + 1)] {
            assert!(matches!(
                line(principal, "view"),
                Err(RelayError::Principal)
            ));
        }
        for request in [
            "",
            " view",
            "view\nKARYOS-AGENT 1 gap-ack 1",
            "view\r",
            "relay alice gap-ack 1",
            &"v".repeat(MAX_REQUEST + 1),
        ] {
            assert!(matches!(line("svc.ops", request), Err(RelayError::Request)));
        }
    }
}
