// SPDX-License-Identifier: Apache-2.0

//! A scripted [`SocketOps`] test double (`quantstratum-docs:
//! karyos/design/sockets-backend.md` 3.9 and section 9): it returns
//! scripted results, so the endpoint's state machine, partial batches and
//! error mapping are tested deterministically, under Miri as well. Test
//! hook only (feature `test-hooks`).
//!
//! A `ScriptedSocket` is a handle to one shared script, like a descriptor
//! to one socket: [`SocketOps::try_clone`] and [`ScriptedSocket::observer`]
//! return handles to the same script and counters, so the two halves of a
//! split endpoint share it and a test inspects it while the endpoint owns
//! its handles. A handle is a live descriptor from a successful
//! [`SocketOps::open`] or `try_clone` until [`SocketOps::close`] or its
//! drop; [`ScriptedSocket::live_descriptors`] counts them.
//!
//! Scripts are stored when they are pushed and consumed by a cursor, so
//! `send` and `recv` neither allocate nor free once the shared lock has
//! been taken on the control path: a counting allocator test of the data
//! path can run over this double. A call with no scripted result left
//! behaves as an idle nonblocking socket, returning `EAGAIN`, and is
//! counted as unscripted. A data call on a handle that is not live returns
//! `EBADF`.

use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::endpoint::{BufferSize, SocketsConfig};
use super::errqueue::ErrEntry;
use super::ops::{Errno, RecvResult, RouteAddr, SendResult, SocketOps, SocketProbes};
use crate::backend::{CapabilityState, EtfQueue, OpenError, Reason};

/// A hook that sees every send call before its scripted result is returned,
/// for example to check the bytes it is handed or to close a guard between
/// the gate check and the system call.
pub type SendHook = Box<dyn FnMut(&RouteAddr, &[&[u8]]) + Send>;

/// A hook that sees every `etf` send call (ADR-0109) with its queue index,
/// bytes and send time before its scripted result is returned.
pub type EtfSendHook = Box<dyn FnMut(u16, &[u8], u64) + Send>;

/// One scripted receive.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ScriptedRecv {
    /// A datagram, delivered as the Linux socket does with `MSG_TRUNC`: the
    /// buffer receives its start, and a datagram that fills or exceeds the
    /// buffer reports its true length.
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

/// The script and counters every handle of one socket shares.
#[derive(Default)]
struct Script {
    sends: Vec<SendResult>,
    next_send: usize,
    recvs: Vec<ScriptedRecv>,
    next_recv: usize,
    opens: Vec<Result<SocketProbes, OpenError>>,
    next_open: usize,
    clone_failures: Vec<Errno>,
    route_mtu: Option<u32>,
    send_calls: u64,
    datagrams_offered: u64,
    unscripted_sends: u64,
    recv_calls: u64,
    unscripted_recvs: u64,
    open_calls: u64,
    live: u64,
    send_hook: Option<SendHook>,
    etf_opens: Vec<Result<(), Reason>>,
    next_etf_open: usize,
    etf_sends: Vec<SendResult>,
    next_etf_send: usize,
    etf_errors: Vec<ErrEntry>,
    next_etf_error: usize,
    etf_send_hook: Option<EtfSendHook>,
    /// Etf sockets opened and not closed, over every queue index.
    etf_live: u64,
    etf_send_calls: u64,
    tai_now_ns: Option<u64>,
}

/// A [`SocketOps`] that returns scripted results and counts its calls.
pub struct ScriptedSocket {
    script: Arc<Mutex<Script>>,
    live: bool,
    /// Etf sockets this handle opened and has not closed.
    etf: u64,
}

/// The probes an unscripted [`SocketOps::open`] returns: the address of
/// the configuration, every probed capability `Active` except RX batching
/// and each buffer request met. The scripted `recv_batch` is the default
/// loop of single receives, not a batch, so RX batching is
/// `Unavailable(LibraryApi)`: the scripted library has no batched receive.
#[must_use]
pub fn default_probes(config: &SocketsConfig) -> SocketProbes {
    let buffer = |requested: Option<std::num::NonZeroU32>| match requested {
        Some(size) => BufferSize {
            requested,
            effective: Some(size.get()),
            state: CapabilityState::Active,
        },
        None => BufferSize::NOT_REQUESTED,
    };
    SocketProbes {
        local: config.local,
        interface: None,
        dont_fragment: CapabilityState::Active,
        tx_batch: CapabilityState::Active,
        rx_batch: CapabilityState::Unavailable(Reason::LibraryApi),
        send_buffer: buffer(config.send_buffer),
        recv_buffer: buffer(config.recv_buffer),
        multicast: config
            .multicast
            .map(|multicast| super::endpoint::Membership {
                group: multicast.group,
                interface: multicast.interface,
            }),
    }
}

impl ScriptedSocket {
    /// A closed socket with empty scripts.
    #[must_use]
    pub fn new() -> Self {
        Self {
            script: Arc::new(Mutex::new(Script::default())),
            live: false,
            etf: 0,
        }
    }

    /// Another handle to the same script and counters that is not a
    /// descriptor: for a test to push results and read counters while the
    /// endpoint owns the live handles.
    #[must_use]
    pub fn observer(&self) -> Self {
        Self {
            script: Arc::clone(&self.script),
            live: false,
            etf: 0,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Script> {
        // A panicking send hook poisons the lock; the script stays usable.
        self.script.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Appends the result of a later send call.
    pub fn push_send(&self, result: SendResult) -> &Self {
        self.lock().sends.push(result);
        self
    }

    /// Appends a datagram for a later receive call, delivered with Linux
    /// `MSG_TRUNC` semantics.
    pub fn push_recv_datagram(&self, payload: &[u8], source: Option<SocketAddr>) -> &Self {
        self.lock().recvs.push(ScriptedRecv::Datagram {
            payload: payload.to_vec(),
            source,
        });
        self
    }

    /// Appends an exact receive result; `payload` is copied into the buffer
    /// first, up to the buffer's length.
    pub fn push_recv(&self, result: RecvResult, payload: &[u8]) -> &Self {
        self.lock().recvs.push(ScriptedRecv::Exact {
            result,
            payload: payload.to_vec(),
        });
        self
    }

    /// Appends the result of a later open call; an unscripted open
    /// succeeds with [`default_probes`].
    pub fn push_open(&self, result: Result<SocketProbes, OpenError>) -> &Self {
        self.lock().opens.push(result);
        self
    }

    /// Makes the next `try_clone` fail with `errno`.
    pub fn fail_next_clone(&self, errno: Errno) -> &Self {
        self.lock().clone_failures.push(errno);
        self
    }

    /// Sets the route MTU every later measurement returns; `None`, the
    /// initial value, is an unmeasured route.
    pub fn set_route_mtu(&self, route_mtu: Option<u32>) -> &Self {
        self.lock().route_mtu = route_mtu;
        self
    }

    /// Installs a hook run at the start of every send call.
    pub fn set_send_hook(&self, hook: SendHook) -> &Self {
        self.lock().send_hook = Some(hook);
        self
    }

    /// Appends the result of a later `open_etf`; an unscripted one
    /// succeeds.
    pub fn push_etf_open(&self, result: Result<(), Reason>) -> &Self {
        self.lock().etf_opens.push(result);
        self
    }

    /// Appends the result of a later `send_etf`; an unscripted one returns
    /// `EAGAIN`.
    pub fn push_etf_send(&self, result: SendResult) -> &Self {
        self.lock().etf_sends.push(result);
        self
    }

    /// Appends an entry a later `drain_etf` returns.
    pub fn push_etf_error(&self, entry: ErrEntry) -> &Self {
        self.lock().etf_errors.push(entry);
        self
    }

    /// Installs a hook run at the start of every `send_etf` call.
    pub fn set_etf_send_hook(&self, hook: EtfSendHook) -> &Self {
        self.lock().etf_send_hook = Some(hook);
        self
    }

    /// Sets what `tai_now_ns` returns; `None`, the initial value, is a
    /// clock that cannot be read.
    pub fn set_tai_now_ns(&self, now: Option<u64>) -> &Self {
        self.lock().tai_now_ns = now;
        self
    }

    /// `send_etf` calls made.
    #[must_use]
    pub fn etf_send_calls(&self) -> u64 {
        self.lock().etf_send_calls
    }

    /// Etf sockets open now, over every queue index.
    #[must_use]
    pub fn etf_live(&self) -> u64 {
        self.lock().etf_live
    }

    /// Send calls made.
    #[must_use]
    pub fn send_calls(&self) -> u64 {
        self.lock().send_calls
    }

    /// Datagrams offered over all send calls, accepted or not.
    #[must_use]
    pub fn datagrams_offered(&self) -> u64 {
        self.lock().datagrams_offered
    }

    /// Send calls made with no scripted result left.
    #[must_use]
    pub fn unscripted_sends(&self) -> u64 {
        self.lock().unscripted_sends
    }

    /// Scripted send results not consumed yet.
    #[must_use]
    pub fn remaining_sends(&self) -> usize {
        let script = self.lock();
        script
            .sends
            .get(script.next_send..)
            .map_or(0, <[SendResult]>::len)
    }

    /// Receive calls made.
    #[must_use]
    pub fn recv_calls(&self) -> u64 {
        self.lock().recv_calls
    }

    /// Receive calls made with no scripted result left.
    #[must_use]
    pub fn unscripted_recvs(&self) -> u64 {
        self.lock().unscripted_recvs
    }

    /// Scripted receive results not consumed yet.
    #[must_use]
    pub fn remaining_recvs(&self) -> usize {
        let script = self.lock();
        script
            .recvs
            .get(script.next_recv..)
            .map_or(0, <[ScriptedRecv]>::len)
    }

    /// Open calls made, failed ones included.
    #[must_use]
    pub fn open_calls(&self) -> u64 {
        self.lock().open_calls
    }

    /// Live descriptors over every handle of the socket.
    #[must_use]
    pub fn live_descriptors(&self) -> u64 {
        self.lock().live
    }

    /// Whether this handle is a live descriptor.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.live
    }
}

impl Default for ScriptedSocket {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ScriptedSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let script = self.lock();
        f.debug_struct("ScriptedSocket")
            .field("live", &self.live)
            .field("sends", &script.sends)
            .field("next_send", &script.next_send)
            .field("recvs", &script.recvs)
            .field("next_recv", &script.next_recv)
            .field("send_calls", &script.send_calls)
            .field("datagrams_offered", &script.datagrams_offered)
            .field("unscripted_sends", &script.unscripted_sends)
            .field("recv_calls", &script.recv_calls)
            .field("unscripted_recvs", &script.unscripted_recvs)
            .field("live_descriptors", &script.live)
            .field("send_hook", &script.send_hook.is_some())
            .finish()
    }
}

impl Drop for ScriptedSocket {
    fn drop(&mut self) {
        self.close();
    }
}

/// Adds to a call counter; a test cannot make `u64::MAX` calls.
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
        let live = self.live;
        let mut guard = self.lock();
        let script = &mut *guard;
        bump(&mut script.send_calls, 1);
        bump(
            &mut script.datagrams_offered,
            u64::try_from(datagrams.len()).unwrap_or(u64::MAX),
        );
        if !live {
            return SendResult::Error(Errno::BADF);
        }
        if let Some(hook) = script.send_hook.as_mut() {
            hook(route, datagrams);
        }
        match script.sends.get(script.next_send) {
            Some(result) => {
                let result = *result;
                bump_cursor(&mut script.next_send);
                result
            }
            None => {
                bump(&mut script.unscripted_sends, 1);
                SendResult::Error(Errno::AGAIN)
            }
        }
    }

    fn recv(&mut self, buffer: &mut [u8]) -> RecvResult {
        let live = self.live;
        let mut guard = self.lock();
        let script = &mut *guard;
        bump(&mut script.recv_calls, 1);
        if !live {
            return RecvResult::Error(Errno::BADF);
        }
        let Some(entry) = script.recvs.get(script.next_recv) else {
            bump(&mut script.unscripted_recvs, 1);
            return RecvResult::Error(Errno::AGAIN);
        };
        let result = match entry {
            ScriptedRecv::Datagram { payload, source } => {
                let len = copy_prefix(buffer, payload);
                let truncated = (payload.len() >= buffer.len()).then_some(payload.len());
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
        };
        bump_cursor(&mut script.next_recv);
        result
    }

    fn open(&mut self, config: &SocketsConfig) -> Result<SocketProbes, OpenError> {
        self.close();
        let mut script = self.lock();
        bump(&mut script.open_calls, 1);
        let result = match script.opens.get(script.next_open) {
            Some(result) => {
                let result = *result;
                bump_cursor(&mut script.next_open);
                result
            }
            None => Ok(default_probes(config)),
        };
        if result.is_ok() {
            bump(&mut script.live, 1);
        }
        drop(script);
        self.live = result.is_ok();
        result
    }

    fn close(&mut self) {
        if self.live {
            self.live = false;
            let own = std::mem::take(&mut self.etf);
            let mut script = self.lock();
            // A closed socket closes its etf sockets, as the Linux one does.
            script.etf_live = script.etf_live.saturating_sub(own);
            // Every live handle was counted when it became live.
            if let Some(live) = script.live.checked_sub(1) {
                script.live = live;
            }
        }
    }

    fn share_recv(&self) -> Result<Box<dyn super::ops::SharedRecv>, Errno> {
        Ok(Box::new(self.try_clone()?))
    }

    fn try_clone(&self) -> Result<Self, Errno> {
        let mut script = self.lock();
        if !self.live {
            return Err(Errno::BADF);
        }
        if !script.clone_failures.is_empty() {
            return Err(script.clone_failures.remove(0));
        }
        bump(&mut script.live, 1);
        Ok(Self {
            script: Arc::clone(&self.script),
            live: true,
            etf: 0,
        })
    }

    fn route_mtu(&mut self, _route: &RouteAddr) -> Option<u32> {
        self.lock().route_mtu
    }

    /// Scripted; counts a live `etf` socket on success. It keeps no table
    /// per queue index: `close_etf` and `close` count them down.
    fn open_etf(&mut self, _queue: u16, _etf: &EtfQueue) -> Result<(), Reason> {
        let mut script = self.lock();
        let result = match script.etf_opens.get(script.next_etf_open) {
            Some(result) => {
                let result = *result;
                bump_cursor(&mut script.next_etf_open);
                result
            }
            None => Ok(()),
        };
        if result.is_ok() {
            bump(&mut script.etf_live, 1);
        }
        drop(script);
        if result.is_ok() {
            bump(&mut self.etf, 1);
        }
        result
    }

    fn close_etf(&mut self, _queue: u16) {
        if let Some(own) = self.etf.checked_sub(1) {
            self.etf = own;
            let mut script = self.lock();
            script.etf_live = script.etf_live.saturating_sub(1);
        }
    }

    fn send_etf(
        &mut self,
        queue: u16,
        _route: &RouteAddr,
        datagram: &[u8],
        txtime_ns: u64,
    ) -> SendResult {
        let live = self.live;
        let mut guard = self.lock();
        let script = &mut *guard;
        bump(&mut script.etf_send_calls, 1);
        if !live {
            return SendResult::Error(Errno::BADF);
        }
        if let Some(hook) = script.etf_send_hook.as_mut() {
            hook(queue, datagram, txtime_ns);
        }
        match script.etf_sends.get(script.next_etf_send) {
            Some(result) => {
                let result = *result;
                bump_cursor(&mut script.next_etf_send);
                result
            }
            None => SendResult::Error(Errno::AGAIN),
        }
    }

    fn drain_etf(&mut self, _queue: u16, out: &mut [ErrEntry]) -> Result<usize, Errno> {
        let mut script = self.lock();
        let mut drained: usize = 0;
        for slot in out.iter_mut() {
            let Some(entry) = script.etf_errors.get(script.next_etf_error).copied() else {
                break;
            };
            *slot = entry;
            bump_cursor(&mut script.next_etf_error);
            drained = drained.saturating_add(1);
        }
        Ok(drained)
    }

    fn tai_now_ns(&mut self) -> Option<u64> {
        self.lock().tai_now_ns
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

    fn live() -> ScriptedSocket {
        let mut socket = ScriptedSocket::new();
        socket
            .open(&SocketsConfig::new(SocketAddr::from((
                Ipv4Addr::LOCALHOST,
                0,
            ))))
            .unwrap();
        socket
    }

    #[test]
    fn sends_return_the_script_in_order_then_would_block() {
        let mut socket = live();
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
        let mut socket = live();
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
        let mut socket = live();
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
    fn a_payload_filling_the_buffer_reports_its_length() {
        let mut socket = live();
        socket.push_recv_datagram(b"abcd", None);
        let mut buffer = [0_u8; 4];
        assert_eq!(
            socket.recv(&mut buffer),
            RecvResult::Datagram {
                len: 4,
                truncated: Some(4),
                source: None
            }
        );
        assert_eq!(&buffer, b"abcd");
    }

    #[test]
    fn handles_share_one_script_and_count_live_descriptors() {
        let mut socket = ScriptedSocket::new();
        let observer = socket.observer();
        let mut buffer = [0_u8; 4];
        // A closed handle is a bad descriptor.
        assert_eq!(socket.recv(&mut buffer), RecvResult::Error(Errno::BADF));
        assert_eq!(socket.try_clone().err(), Some(Errno::BADF));
        socket
            .open(&SocketsConfig::new(SocketAddr::from((
                Ipv4Addr::LOCALHOST,
                0,
            ))))
            .unwrap();
        observer.fail_next_clone(Errno::NOMEM);
        assert_eq!(socket.try_clone().err(), Some(Errno::NOMEM));
        let mut duplicate = socket.try_clone().unwrap();
        assert_eq!(observer.live_descriptors(), 2);
        observer.push_recv_datagram(b"x", None);
        assert!(matches!(
            duplicate.recv(&mut buffer),
            RecvResult::Datagram { len: 1, .. }
        ));
        drop(duplicate);
        assert_eq!(observer.live_descriptors(), 1);
        assert_eq!(observer.recv_calls(), 2);
        socket.close();
        socket.close();
        assert_eq!(observer.live_descriptors(), 0);
        assert!(!socket.is_live());
        assert_eq!(observer.open_calls(), 1);
        assert_eq!(socket.route_mtu(&route()), None);
        observer.set_route_mtu(Some(1500));
        assert_eq!(socket.route_mtu(&route()), Some(1500));
        observer.push_open(Err(OpenError::Os {
            operation: "bind",
            errno: Errno::ADDRNOTAVAIL.raw(),
        }));
        assert!(
            socket
                .open(&SocketsConfig::new(SocketAddr::from((
                    Ipv4Addr::LOCALHOST,
                    0
                ))))
                .is_err()
        );
        assert_eq!(observer.live_descriptors(), 0);
    }
}
