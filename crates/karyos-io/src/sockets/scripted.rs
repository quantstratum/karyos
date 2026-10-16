// SPDX-License-Identifier: Apache-2.0

//! A scripted [`SocketOps`] test double (`quantstratum-docs:
//! karyos/design/sockets-backend.md` 3.9 and section 9): it returns
//! scripted results, so the endpoint's state machine, partial batches and
//! error mapping are tested deterministically, under Miri as well. Test
//! hook only (feature `test-hooks`).
//!
//! Scripts are stored when they are pushed and consumed by a cursor, so
//! `send` and `recv` neither allocate nor free: a counting allocator test
//! of the data path can run over this double. A call with no scripted
//! result left behaves as an idle nonblocking socket, returning `EAGAIN`,
//! and is counted as unscripted.

use std::fmt;
use std::net::SocketAddr;

use super::ops::{Errno, RecvResult, RouteAddr, SendResult, SocketOps};

/// A hook that sees every send call before its scripted result is returned,
/// for example to check the bytes it is handed or to close a guard between
/// the gate check and the system call.
pub type SendHook = Box<dyn FnMut(&RouteAddr, &[&[u8]]) + Send>;

/// One scripted receive.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ScriptedRecv {
    /// A datagram, delivered as the Linux kernel does with `MSG_TRUNC`: the
    /// buffer receives its start, and a datagram longer than the buffer
    /// reports its true length.
    Datagram {
        payload: Vec<u8>,
        source: Option<SocketAddr>,
    },
    /// An exact result; `payload` is copied into the buffer first, up to
    /// its length.
    Exact {
        result: RecvResult,
        payload: Vec<u8>,
    },
}

/// A [`SocketOps`] that returns scripted results and counts its calls.
pub struct ScriptedSocket {
    sends: Vec<SendResult>,
    next_send: usize,
    recvs: Vec<ScriptedRecv>,
    next_recv: usize,
    send_calls: u64,
    datagrams_offered: u64,
    unscripted_sends: u64,
    recv_calls: u64,
    unscripted_recvs: u64,
    send_hook: Option<SendHook>,
}

impl ScriptedSocket {
    /// A socket with empty scripts.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sends: Vec::new(),
            next_send: 0,
            recvs: Vec::new(),
            next_recv: 0,
            send_calls: 0,
            datagrams_offered: 0,
            unscripted_sends: 0,
            recv_calls: 0,
            unscripted_recvs: 0,
            send_hook: None,
        }
    }

    /// Appends the result of a later send call.
    pub fn push_send(&mut self, result: SendResult) -> &mut Self {
        self.sends.push(result);
        self
    }

    /// Appends a datagram for a later receive call, delivered with Linux
    /// `MSG_TRUNC` semantics.
    pub fn push_recv_datagram(&mut self, payload: &[u8], source: Option<SocketAddr>) -> &mut Self {
        self.recvs.push(ScriptedRecv::Datagram {
            payload: payload.to_vec(),
            source,
        });
        self
    }

    /// Appends an exact receive result; `payload` is copied into the buffer
    /// first, up to the buffer's length.
    pub fn push_recv(&mut self, result: RecvResult, payload: &[u8]) -> &mut Self {
        self.recvs.push(ScriptedRecv::Exact {
            result,
            payload: payload.to_vec(),
        });
        self
    }

    /// Installs a hook run at the start of every send call.
    pub fn set_send_hook(&mut self, hook: SendHook) -> &mut Self {
        self.send_hook = Some(hook);
        self
    }

    /// Send calls made.
    #[must_use]
    pub fn send_calls(&self) -> u64 {
        self.send_calls
    }

    /// Datagrams offered over all send calls, accepted or not.
    #[must_use]
    pub fn datagrams_offered(&self) -> u64 {
        self.datagrams_offered
    }

    /// Send calls made with no scripted result left.
    #[must_use]
    pub fn unscripted_sends(&self) -> u64 {
        self.unscripted_sends
    }

    /// Scripted send results not consumed yet.
    #[must_use]
    pub fn remaining_sends(&self) -> usize {
        self.sends
            .get(self.next_send..)
            .map_or(0, <[SendResult]>::len)
    }

    /// Receive calls made.
    #[must_use]
    pub fn recv_calls(&self) -> u64 {
        self.recv_calls
    }

    /// Receive calls made with no scripted result left.
    #[must_use]
    pub fn unscripted_recvs(&self) -> u64 {
        self.unscripted_recvs
    }

    /// Scripted receive results not consumed yet.
    #[must_use]
    pub fn remaining_recvs(&self) -> usize {
        self.recvs
            .get(self.next_recv..)
            .map_or(0, <[ScriptedRecv]>::len)
    }
}

impl Default for ScriptedSocket {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ScriptedSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptedSocket")
            .field("sends", &self.sends)
            .field("next_send", &self.next_send)
            .field("recvs", &self.recvs)
            .field("next_recv", &self.next_recv)
            .field("send_calls", &self.send_calls)
            .field("datagrams_offered", &self.datagrams_offered)
            .field("unscripted_sends", &self.unscripted_sends)
            .field("recv_calls", &self.recv_calls)
            .field("unscripted_recvs", &self.unscripted_recvs)
            .field("send_hook", &self.send_hook.is_some())
            .finish()
    }
}

/// Adds one to a call counter; a test cannot make `u64::MAX` calls.
fn bump(counter: &mut u64, by: u64) {
    if let Some(next) = counter.checked_add(by) {
        *counter = next;
    }
}

/// Moves a script cursor past one consumed entry; it stays at most the
/// script's length.
fn bump_cursor(cursor: &mut usize) {
    if let Some(next) = cursor.checked_add(1) {
        *cursor = next;
    }
}

/// Copies the start of `payload` into `buffer` and returns the bytes copied.
fn copy_prefix(buffer: &mut [u8], payload: &[u8]) -> usize {
    let len = payload.len().min(buffer.len());
    if let (Some(to), Some(from)) = (buffer.get_mut(..len), payload.get(..len)) {
        to.copy_from_slice(from);
    }
    len
}

impl SocketOps for ScriptedSocket {
    fn send(&mut self, route: &RouteAddr, datagrams: &[&[u8]]) -> SendResult {
        bump(&mut self.send_calls, 1);
        bump(
            &mut self.datagrams_offered,
            u64::try_from(datagrams.len()).unwrap_or(u64::MAX),
        );
        if let Some(hook) = self.send_hook.as_mut() {
            hook(route, datagrams);
        }
        match self.sends.get(self.next_send) {
            Some(result) => {
                bump_cursor(&mut self.next_send);
                *result
            }
            None => {
                bump(&mut self.unscripted_sends, 1);
                SendResult::Error(Errno::AGAIN)
            }
        }
    }

    fn recv(&mut self, buffer: &mut [u8]) -> RecvResult {
        bump(&mut self.recv_calls, 1);
        let Some(script) = self.recvs.get(self.next_recv) else {
            bump(&mut self.unscripted_recvs, 1);
            return RecvResult::Error(Errno::AGAIN);
        };
        bump_cursor(&mut self.next_recv);
        match script {
            ScriptedRecv::Datagram { payload, source } => {
                let len = copy_prefix(buffer, payload);
                let truncated = (payload.len() > buffer.len()).then_some(payload.len());
                RecvResult::Datagram {
                    len,
                    truncated,
                    source: *source,
                }
            }
            ScriptedRecv::Exact { result, payload } => {
                copy_prefix(buffer, payload);
                *result
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn route() -> RouteAddr {
        RouteAddr::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 7000)))
    }

    #[test]
    fn sends_return_the_script_in_order_then_would_block() {
        let mut socket = ScriptedSocket::new();
        socket
            .push_send(SendResult::Sent {
                sent: 1,
                error: Some(Errno::MSGSIZE),
            })
            .push_send(SendResult::Error(Errno::INTR));
        assert_eq!(socket.remaining_sends(), 2);
        let datagrams: [&[u8]; 2] = [b"ab", b"c"];
        assert_eq!(
            socket.send(&route(), &datagrams),
            SendResult::Sent {
                sent: 1,
                error: Some(Errno::MSGSIZE)
            }
        );
        assert_eq!(
            socket.send(&route(), &datagrams[1..]),
            SendResult::Error(Errno::INTR)
        );
        assert_eq!(socket.send(&route(), &[]), SendResult::Error(Errno::AGAIN));
        assert_eq!(socket.send_calls(), 3);
        assert_eq!(socket.datagrams_offered(), 3);
        assert_eq!(socket.unscripted_sends(), 1);
        assert_eq!(socket.remaining_sends(), 0);
    }

    #[test]
    fn the_send_hook_sees_every_call_and_its_bytes() {
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&seen);
        let mut socket = ScriptedSocket::default();
        socket.set_send_hook(Box::new(move |route, datagrams| {
            assert_eq!(route.address().port(), 7000);
            assert_eq!(datagrams, [b"xyz".as_slice()]);
            counter.fetch_add(1, Ordering::Relaxed);
        }));
        socket.send(&route(), &[b"xyz"]);
        socket.send(&route(), &[b"xyz"]);
        assert_eq!(seen.load(Ordering::Relaxed), 2);
        assert!(format!("{socket:?}").contains("send_hook: true"));
    }

    #[test]
    fn datagrams_report_truncation_like_msg_trunc() {
        let source = Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)));
        let mut socket = ScriptedSocket::new();
        socket
            .push_recv_datagram(b"abc", source)
            .push_recv_datagram(b"abcdef", None)
            .push_recv(RecvResult::Error(Errno::NOBUFS), &[])
            .push_recv(
                RecvResult::Datagram {
                    len: 4,
                    truncated: None,
                    source: None,
                },
                b"wxyz!",
            );
        let mut buffer = [0_u8; 4];
        assert_eq!(
            socket.recv(&mut buffer),
            RecvResult::Datagram {
                len: 3,
                truncated: None,
                source
            }
        );
        assert_eq!(&buffer[..3], b"abc");
        assert_eq!(
            socket.recv(&mut buffer),
            RecvResult::Datagram {
                len: 4,
                truncated: Some(6),
                source: None
            }
        );
        assert_eq!(&buffer, b"abcd");
        assert_eq!(socket.recv(&mut buffer), RecvResult::Error(Errno::NOBUFS));
        assert_eq!(
            socket.recv(&mut buffer),
            RecvResult::Datagram {
                len: 4,
                truncated: None,
                source: None
            }
        );
        assert_eq!(&buffer, b"wxyz");
        assert_eq!(socket.remaining_recvs(), 0);
        assert_eq!(socket.recv(&mut buffer), RecvResult::Error(Errno::AGAIN));
        assert_eq!((socket.recv_calls(), socket.unscripted_recvs()), (5, 1));
    }

    #[test]
    fn a_payload_as_long_as_the_buffer_is_not_truncated() {
        let mut socket = ScriptedSocket::new();
        socket.push_recv_datagram(b"abcd", None);
        let mut buffer = [0_u8; 4];
        assert_eq!(
            socket.recv(&mut buffer),
            RecvResult::Datagram {
                len: 4,
                truncated: None,
                source: None
            }
        );
        assert_eq!(&buffer, b"abcd");
    }
}
