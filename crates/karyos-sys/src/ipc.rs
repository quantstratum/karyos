// SPDX-License-Identifier: Apache-2.0

//! Cross-process IPC primitives (Linux): regions and descriptor passing
//! (`quantstratum-docs: karyos/design/ipc-implementation.md`, i1; `quantstratum-docs: karyos/design/ipc-admission.md`).
//!
//! A [`Region`] is one `memfd` that the driver creates, sizes, stamps with a
//! 64-byte header and seals against resizing (`F_SEAL_SHRINK | F_SEAL_GROW
//! | F_SEAL_SEAL`, the "size seals") before any participant sees it. Unlike
//! the local [`crate::mmap::SealedMapping`], it carries no write seal:
//! participants in other processes need writable mappings of it
//! (ADR-0045). A participant attaches a received descriptor only after the
//! exact seals, the exact size and then the header match the record it
//! expects. Every access to the region is an aligned atomic word access
//! through [`AtomicWords`]; no slice or reference to its bytes exists.
//!
//! The transport sends one `SOCK_SEQPACKET` message with at most one
//! descriptor, and receives with a control buffer for exactly one: every
//! received descriptor is owned at once (an [`OwnedFd`], closed on drop),
//! and any violation drops every descriptor of the datagram.
//!
//! Size seals are kernel seals, distinct from the protocol's `Sealed`
//! mapping state (ADR-0013).

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;
use std::io::{IoSlice, IoSliceMut};

use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{MemfdFlags, SealFlags};
use rustix::mm::{Advice, MapFlags, ProtFlags};
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags, SocketType,
};

use crate::atomic_view::{AtomicWords, WORD_BYTES};
use crate::error::SysError;

/// Bytes before a region's structure: the 64-byte header, padded to the
/// 128-byte stride (`quantstratum-docs: karyos/design/cnc-primitives.md`).
pub const HEADER_STRIDE: usize = 128;
/// Words of the header.
const HEADER_WORDS: usize = 8;
/// The first header word of every region: "KARYOS" and a format byte.
pub const REGION_MAGIC: u64 = u64::from_le_bytes(*b"KARYOSr1");

/// The kernel seals a region must carry: exactly these, plus `F_SEAL_EXEC`
/// when the kernel adds it for a non-executable `memfd`.
const SIZE_SEALS: SealFlags = SealFlags::SHRINK
    .union(SealFlags::GROW)
    .union(SealFlags::SEAL);

/// What a region holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// A client's command ring.
    CommandRing,
    /// The broadcast buffer.
    Broadcast,
    /// The counters.
    Counters,
    /// One log buffer generation.
    LogBuffer,
}

impl RegionKind {
    const fn code(self) -> u64 {
        match self {
            Self::CommandRing => 1,
            Self::Broadcast => 2,
            Self::Counters => 3,
            Self::LogBuffer => 4,
        }
    }
}

/// What a region's header says, and what a participant expects of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionRecord {
    /// The driver instance that created it.
    pub instance: u128,
    /// Its id, unique within the driver instance.
    pub region: u64,
    /// What it holds.
    pub kind: RegionKind,
    /// Its mapping generation (log buffers; 0 otherwise).
    pub generation: u64,
    /// The layout version of its structure.
    pub layout: u64,
    /// Bytes of its structure after the header stride: a nonzero multiple
    /// of 128.
    pub structure_length: usize,
}

impl RegionRecord {
    /// The region's total size: the header stride plus the structure.
    fn size(&self) -> Result<usize, SysError> {
        let len = self.structure_length;
        if len == 0 || !len.is_multiple_of(HEADER_STRIDE) {
            return Err(SysError::InvalidRegion { address: 0, len });
        }
        HEADER_STRIDE
            .checked_add(len)
            .filter(|total| isize::try_from(*total).is_ok())
            .ok_or(SysError::InvalidRegion { address: 0, len })
    }

    fn header_words(&self) -> [u64; HEADER_WORDS] {
        [
            REGION_MAGIC,
            self.instance as u64,
            (self.instance >> 64) as u64,
            self.region,
            self.kind.code(),
            self.generation,
            self.layout,
            self.structure_length as u64,
        ]
    }
}

/// A mapped region, viewed only as atomic words.
#[derive(Debug)]
pub struct Region {
    base: NonNull<u8>,
    len: usize,
    record: RegionRecord,
    /// The creator keeps the descriptor to pass it; a participant closes it
    /// right after mapping.
    fd: Option<OwnedFd>,
}

// SAFETY: the mapping is process-wide memory, valid from any thread until
// `drop`. `Region` exposes it only through `AtomicWords`, i.e. shared
// references to `AtomicU64`, which are `Send` and `Sync`. No other state is
// shared without synchronization.
unsafe impl Send for Region {}
// SAFETY: see the `Send` impl.
unsafe impl Sync for Region {}

impl Region {
    /// Creates a region for `record` (driver side): a fresh sealable
    /// `memfd` of `128 + structure_length` bytes, mapped shared read-write,
    /// zero-filled, stamped with the header, then size-sealed and checked.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidRegion`] for an invalid structure length,
    /// [`SysError::SealMismatch`] when the kernel does not apply the size
    /// seals, and [`SysError::Os`] when a system call fails. Everything
    /// acquired before a failure is released.
    pub fn create(record: RegionRecord) -> Result<Self, SysError> {
        let len = record.size()?;
        let file_len =
            u64::try_from(len).map_err(|_| SysError::InvalidRegion { address: 0, len })?;
        let fd = create_memfd()?;
        rustix::fs::ftruncate(&fd, file_len).map_err(os("ftruncate"))?;
        let region = Self::map(fd, len, record)?;
        let words = region.words_checked()?;
        for (index, value) in record.header_words().into_iter().enumerate() {
            if let Some(word) = words.get(index) {
                word.store(value, Ordering::Release);
            }
        }
        let Some(fd) = region.fd.as_ref() else {
            return Err(SysError::InvalidRegion { address: 0, len });
        };
        rustix::fs::fcntl_add_seals(fd, SIZE_SEALS).map_err(os("fcntl_add_seals"))?;
        check_seals(fd)?;
        Ok(region)
    }

    /// Attaches a received descriptor (participant side), in the order of
    /// `quantstratum-docs: karyos/design/ipc-admission.md`: the exact size seals, the exact size
    /// for `expected`, one whole mapping followed at once by
    /// `MADV_DONTFORK`, the descriptor closed, then the header compared with
    /// `expected` by atomic loads.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::SealMismatch`], [`SysError::InvalidRegion`] (a
    /// size or header that does not match) or [`SysError::Os`]. The
    /// descriptor is closed and any mapping undone on every error.
    pub fn attach(fd: OwnedFd, expected: RegionRecord) -> Result<Self, SysError> {
        let len = expected.size()?;
        check_seals(&fd)?;
        let stat = rustix::fs::fstat(&fd).map_err(os("fstat"))?;
        if u64::try_from(stat.st_size).ok() != u64::try_from(len).ok() {
            return Err(SysError::InvalidRegion {
                address: 0,
                len: usize::try_from(stat.st_size).unwrap_or(usize::MAX),
            });
        }
        let mut region = Self::map(fd, len, expected)?;
        // Closed once mapped: the mapping keeps the memory alive.
        region.fd = None;
        let words = region.words_checked()?;
        let matches = expected
            .header_words()
            .into_iter()
            .enumerate()
            .all(|(index, value)| {
                words
                    .get(index)
                    .is_some_and(|word| word.load(Ordering::Acquire) == value)
            });
        if !matches {
            return Err(SysError::InvalidRegion { address: 0, len });
        }
        Ok(region)
    }

    /// Maps `len` bytes of `fd` shared read-write, then advises
    /// `MADV_DONTFORK` before anything else.
    fn map(fd: OwnedFd, len: usize, record: RegionRecord) -> Result<Self, SysError> {
        // SAFETY: a fresh mapping at an address chosen by the kernel (null
        // hint) over `len` bytes of a file whose size is `len` (checked or
        // set by the caller) and, once size-sealed, can never change. It
        // aliases no existing Rust object.
        let raw = unsafe {
            rustix::mm::mmap(
                core::ptr::null_mut(),
                len,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED,
                &fd,
                0,
            )
        }
        .map_err(os("mmap"))?;
        let Some(base) = NonNull::new(raw.cast::<u8>()) else {
            // SAFETY: unmaps exactly the range just mapped, which nothing
            // references.
            let _ = unsafe { rustix::mm::munmap(raw, len) };
            return Err(SysError::InvalidRegion { address: 0, len });
        };
        // From here `region` owns the mapping; an early return unmaps it.
        let region = Self {
            base,
            len,
            record,
            fd: Some(fd),
        };
        // SAFETY: advises exactly the range this object maps; the advice
        // changes no contents.
        unsafe { rustix::mm::madvise(raw, len, Advice::LinuxDontFork) }.map_err(os("madvise"))?;
        Ok(region)
    }

    /// The record the region was created or attached for.
    #[inline]
    #[must_use]
    pub fn record(&self) -> RegionRecord {
        self.record
    }

    /// The descriptor to pass to a participant: the creator's only.
    #[must_use]
    pub fn descriptor(&self) -> Option<BorrowedFd<'_>> {
        self.fd.as_ref().map(AsFd::as_fd)
    }

    /// The region's structure: the words after the header stride.
    #[must_use]
    pub fn structure(&self) -> AtomicWords<'_> {
        match self.words_checked() {
            Ok(words) => words.slice_from(HEADER_STRIDE / WORD_BYTES),
            // `create` or `attach` validated the same region.
            Err(_) => AtomicWords::empty(),
        }
    }

    fn words_checked(&self) -> Result<AtomicWords<'_>, SysError> {
        // SAFETY: `base..base + len` is mapped read-write for as long as
        // `self` lives (unmapped only in `drop`), the backing is size-sealed
        // (or, during `create`, not yet shared and sized exactly `len`), the
        // view borrows `self`, and this process accesses the region only
        // through `AtomicWords`.
        unsafe { AtomicWords::from_raw(self.base.as_ptr(), self.len) }
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        // SAFETY: unmaps exactly the range mapped in `map`, once. No view
        // outlives `self`, because every view borrows it.
        let _ = unsafe { rustix::mm::munmap(self.base.as_ptr().cast::<c_void>(), self.len) };
    }
}

/// Exactly the size seals, ignoring `F_SEAL_EXEC`.
fn check_seals(fd: &OwnedFd) -> Result<(), SysError> {
    let found = rustix::fs::fcntl_get_seals(fd).map_err(os("fcntl_get_seals"))?;
    if found.difference(SealFlags::EXEC) == SIZE_SEALS {
        Ok(())
    } else {
        Err(SysError::SealMismatch {
            expected: SIZE_SEALS.bits(),
            found: found.bits(),
        })
    }
}

fn create_memfd() -> Result<OwnedFd, SysError> {
    let base = MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING;
    match rustix::fs::memfd_create("karyos-region", base | MemfdFlags::NOEXEC_SEAL) {
        Ok(fd) => Ok(fd),
        Err(rustix::io::Errno::INVAL) => {
            rustix::fs::memfd_create("karyos-region", base).map_err(os("memfd_create"))
        }
        Err(errno) => Err(os("memfd_create")(errno)),
    }
}

fn os(operation: &'static str) -> impl Fn(rustix::io::Errno) -> SysError {
    move |errno| SysError::Os {
        operation,
        errno: errno.raw_os_error(),
    }
}

/// A connected pair of `SOCK_SEQPACKET` Unix sockets, close-on-exec.
///
/// # Errors
///
/// Returns [`SysError::Os`] when `socketpair` fails.
pub fn seqpacket_pair() -> Result<(OwnedFd, OwnedFd), SysError> {
    rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(os("socketpair"))
}

/// Whether a message went out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    /// The whole message was sent.
    Sent,
    /// The socket is non-blocking and full: nothing was sent; keep the
    /// message and try again later.
    WouldBlock,
}

/// Sends one message with at most one descriptor.
///
/// # Errors
///
/// Returns [`SysError::Os`] when `sendmsg` fails, and
/// [`SysError::Protocol`] for an empty message (a receiver could not tell
/// it from a shutdown) or when the kernel took only part of the message.
pub fn send(
    socket: BorrowedFd<'_>,
    bytes: &[u8],
    fd: Option<BorrowedFd<'_>>,
) -> Result<Sent, SysError> {
    if bytes.is_empty() {
        return Err(SysError::Protocol {
            reason: "empty message",
        });
    }
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let fds = fd.as_slice();
    if !fds.is_empty() && !control.push(SendAncillaryMessage::ScmRights(fds)) {
        return Err(SysError::Protocol {
            reason: "control buffer too small for one descriptor",
        });
    }
    match rustix::net::sendmsg(
        socket,
        &[IoSlice::new(bytes)],
        &mut control,
        SendFlags::NOSIGNAL,
    ) {
        Ok(sent) if sent == bytes.len() => Ok(Sent::Sent),
        Ok(_) => Err(SysError::Protocol {
            reason: "partial seqpacket send",
        }),
        Err(rustix::io::Errno::AGAIN) => Ok(Sent::WouldBlock),
        Err(errno) => Err(os("sendmsg")(errno)),
    }
}

/// One received message: its length in the caller's buffer and its
/// descriptor, if it carried one.
#[derive(Debug)]
pub struct Received {
    /// Bytes of the message.
    pub len: usize,
    /// The descriptor, owned: dropping it closes it.
    pub fd: Option<OwnedFd>,
}

/// What a receive found.
#[derive(Debug)]
pub enum Recv {
    /// One message.
    Message(Received),
    /// A non-blocking socket has nothing now.
    WouldBlock,
    /// The peer closed the connection (or sent an empty record, which the
    /// protocol never does: [`send`] refuses empty messages, so an empty
    /// record without a descriptor is read as the orderly shutdown it is
    /// indistinguishable from).
    PeerClosed,
}

/// Receives one message into `buffer`, with at most one descriptor.
///
/// # Errors
///
/// Returns [`SysError::Protocol`] for a truncated message or control data,
/// more than one descriptor, or any other control message (every
/// descriptor received in that datagram is closed), and [`SysError::Os`]
/// when `recvmsg` fails.
pub fn recv(socket: BorrowedFd<'_>, buffer: &mut [u8]) -> Result<Recv, SysError> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let message = match rustix::net::recvmsg(
        socket,
        &mut [IoSliceMut::new(buffer)],
        &mut control,
        RecvFlags::CMSG_CLOEXEC,
    ) {
        Ok(message) => message,
        Err(rustix::io::Errno::AGAIN) => return Ok(Recv::WouldBlock),
        Err(errno) => return Err(os("recvmsg")(errno)),
    };
    // Every descriptor the kernel installed is owned here first, so every
    // return below closes those not handed out.
    let mut fds: Vec<OwnedFd> = Vec::new();
    let mut other = false;
    for item in control.drain() {
        match item {
            RecvAncillaryMessage::ScmRights(received) => fds.extend(received),
            _ => other = true,
        }
    }
    if message.flags.contains(ReturnFlags::CTRUNC) {
        return Err(SysError::Protocol {
            reason: "truncated control data",
        });
    }
    if message.flags.contains(ReturnFlags::TRUNC) || message.bytes > buffer.len() {
        return Err(SysError::Protocol {
            reason: "truncated message",
        });
    }
    if other {
        return Err(SysError::Protocol {
            reason: "unexpected control message",
        });
    }
    if message.bytes == 0 && fds.is_empty() {
        // An orderly shutdown of the peer.
        return Ok(Recv::PeerClosed);
    }
    let fd = fds.pop();
    if !fds.is_empty() {
        return Err(SysError::Protocol {
            reason: "more than one descriptor",
        });
    }
    Ok(Recv::Message(Received {
        len: message.bytes,
        fd,
    }))
}

/// The peer's credentials (`SO_PEERCRED`), cached by the kernel at connect
/// time.
///
/// # Errors
///
/// Returns [`SysError::Os`] when `getsockopt` fails.
pub fn peer_credentials(socket: BorrowedFd<'_>) -> Result<rustix::net::UCred, SysError> {
    rustix::net::sockopt::socket_peercred(socket).map_err(os("getsockopt(SO_PEERCRED)"))
}

/// The file name of the driver's admission socket in its directory.
pub const SOCKET_NAME: &str = "driver.sock";

/// The effective uid of this process.
#[must_use]
pub fn own_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Checks that `path` is a directory (not a symbolic link) owned by this
/// uid with mode `0700`.
fn check_private_dir(path: &std::path::Path) -> Result<(), SysError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path).map_err(io_error("stat(dir)"))?;
    if !metadata.is_dir() || metadata.uid() != own_uid() || metadata.mode() & 0o777 != 0o700 {
        return Err(SysError::Protocol {
            reason: "the socket directory is not a private directory of this uid",
        });
    }
    Ok(())
}

/// Whether `metadata` is a socket of this uid with mode `0600`.
fn owned_socket(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    metadata.file_type().is_socket()
        && metadata.uid() == own_uid()
        && metadata.mode() & 0o777 == 0o600
}

fn io_error(operation: &'static str) -> impl Fn(std::io::Error) -> SysError {
    move |error| SysError::Os {
        operation,
        errno: error.raw_os_error().unwrap_or(0),
    }
}

fn unix_address(path: &std::path::Path) -> Result<rustix::net::SocketAddrUnix, SysError> {
    rustix::net::SocketAddrUnix::new(path).map_err(os("sockaddr_un"))
}

fn seqpacket(flags: SocketFlags) -> Result<OwnedFd, SysError> {
    rustix::net::socket_with(AddressFamily::UNIX, SocketType::SEQPACKET, flags, None)
        .map_err(os("socket"))
}

/// The driver's admission socket in `dir` (`quantstratum-docs: karyos/design/ipc-admission.md`):
/// the directory is created with mode `0700` if absent and must otherwise
/// be a private directory of this uid; the socket, `0600`, non-blocking
/// and close-on-exec, listens with `backlog`. A socket file of a live
/// driver is never replaced; one that refuses connections is stale and
/// removed first.
///
/// # Errors
///
/// Returns [`SysError::Protocol`] for a directory that is not private or a
/// socket of a live driver, and [`SysError::Os`] when a call fails.
pub fn listen(dir: &std::path::Path, backlog: i32) -> Result<OwnedFd, SysError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io_error("mkdir")(error)),
    }
    check_private_dir(dir)?;
    let path = dir.join(SOCKET_NAME);
    let address = unix_address(&path)?;
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error("stat(socket)")(error)),
        Ok(metadata) => {
            // Only a socket of this uid with the driver's mode is ever
            // replaced; anything else at the path is left alone.
            if !owned_socket(&metadata) {
                return Err(SysError::Protocol {
                    reason: "the socket path holds something other than a driver socket",
                });
            }
            // A non-blocking probe: a live driver with a full backlog
            // answers `EAGAIN` at once instead of blocking the start.
            let probe = seqpacket(SocketFlags::CLOEXEC | SocketFlags::NONBLOCK)?;
            match rustix::net::connect(&probe, &address) {
                Ok(()) | Err(rustix::io::Errno::AGAIN) => {
                    return Err(SysError::Protocol {
                        reason: "a live driver holds the socket",
                    });
                }
                Err(rustix::io::Errno::CONNREFUSED) => {
                    std::fs::remove_file(&path).map_err(io_error("unlink(socket)"))?;
                }
                Err(errno) => return Err(os("connect(probe)")(errno)),
            }
        }
    }
    let listener = seqpacket(SocketFlags::CLOEXEC | SocketFlags::NONBLOCK)?;
    rustix::net::bind(&listener, &address).map_err(os("bind"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(io_error("chmod(socket)"))?;
    rustix::net::listen(&listener, backlog).map_err(os("listen"))?;
    Ok(listener)
}

/// Accepts one pending connection, non-blocking and close-on-exec; `None`
/// when none is pending.
///
/// # Errors
///
/// Returns [`SysError::Os`] when `accept` fails otherwise.
pub fn accept(listener: BorrowedFd<'_>) -> Result<Option<OwnedFd>, SysError> {
    match rustix::net::accept_with(listener, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK) {
        Ok(socket) => Ok(Some(socket)),
        Err(rustix::io::Errno::AGAIN) => Ok(None),
        Err(errno) => Err(os("accept")(errno)),
    }
}

/// Connects to the driver's admission socket in `dir` (client side,
/// `quantstratum-docs: karyos/design/ipc-admission.md`): the directory must be a private
/// directory of this uid, the socket a socket of this uid with mode
/// `0600`, and the connected peer (`SO_PEERCRED`) this uid. The connection
/// attempt is bounded by `timeout` (a full backlog is retried, never waited
/// on without bound); the socket is then blocking with `timeout` on every
/// receive and send; close-on-exec.
///
/// # Errors
///
/// Returns [`SysError::Protocol`] when a check fails, and [`SysError::Os`]
/// when a call fails.
pub fn connect(dir: &std::path::Path, timeout: core::time::Duration) -> Result<OwnedFd, SysError> {
    check_private_dir(dir)?;
    let path = dir.join(SOCKET_NAME);
    let metadata = std::fs::symlink_metadata(&path).map_err(io_error("stat(socket)"))?;
    if !owned_socket(&metadata) {
        return Err(SysError::Protocol {
            reason: "the admission socket is not a socket of this uid with mode 0600",
        });
    }
    // Non-blocking, so a full listen backlog (`EAGAIN`) is retried until
    // `timeout` instead of blocking without bound.
    let socket = seqpacket(SocketFlags::CLOEXEC | SocketFlags::NONBLOCK)?;
    let address = unix_address(&path)?;
    let start = std::time::Instant::now();
    loop {
        match rustix::net::connect(&socket, &address) {
            Ok(()) => break,
            Err(rustix::io::Errno::AGAIN) if start.elapsed() < timeout => {
                std::thread::sleep(core::time::Duration::from_millis(1));
            }
            Err(errno) => return Err(os("connect")(errno)),
        }
    }
    rustix::io::ioctl_fionbio(&socket, false).map_err(os("ioctl(FIONBIO)"))?;
    if peer_credentials(socket.as_fd())?.uid.as_raw() != own_uid() {
        return Err(SysError::Protocol {
            reason: "the driver runs as another uid",
        });
    }
    for (kind, operation) in [
        (
            rustix::net::sockopt::Timeout::Recv,
            "setsockopt(SO_RCVTIMEO)",
        ),
        (
            rustix::net::sockopt::Timeout::Send,
            "setsockopt(SO_SNDTIMEO)",
        ),
    ] {
        rustix::net::sockopt::set_socket_timeout(&socket, kind, Some(timeout))
            .map_err(os(operation))?;
    }
    Ok(socket)
}

/// A descriptor known to be a pidfd: the client's exit proof
/// (`quantstratum-docs: karyos/design/ipc-admission.md`). Validated once, when it is built, so
/// [`PidFd::exited`] never mistakes another readable descriptor for an
/// exited process.
#[derive(Debug)]
pub struct PidFd {
    fd: OwnedFd,
    pid: i32,
}

impl PidFd {
    /// A pidfd of this process (`pidfd_open(getpid())`), the descriptor a
    /// client passes with `Hello`. Close-on-exec, as every pidfd.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::Os`] when `pidfd_open` fails (Linux before 5.3).
    pub fn of_self() -> Result<Self, SysError> {
        let fd = rustix::process::pidfd_open(
            rustix::process::getpid(),
            rustix::process::PidfdFlags::empty(),
        )
        .map_err(os("pidfd_open"))?;
        Self::validate(fd)
    }

    /// A pidfd of process `pid` (test hook: a driver never opens a pidfd by
    /// pid, which could name a reused pid; it validates the one it
    /// receives).
    ///
    /// # Errors
    ///
    /// Returns [`SysError::Os`] when `pidfd_open` fails.
    #[cfg(feature = "test-hooks")]
    pub fn open(pid: i32) -> Result<Self, SysError> {
        let pid = rustix::process::Pid::from_raw(pid).ok_or(SysError::Protocol {
            reason: "not a pid",
        })?;
        let fd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
            .map_err(os("pidfd_open"))?;
        Self::validate(fd)
    }

    /// Validates a received descriptor as a process pidfd of a process not
    /// yet reaped: its `fdinfo` has a `Pid:` field naming a positive pid,
    /// and it is not a thread pidfd (`PIDFD_THREAD`). A descriptor that is
    /// not a pidfd, a thread pidfd, or one whose process is already reaped
    /// is refused (and closed).
    ///
    /// # Errors
    ///
    /// Returns [`SysError::Os`] when the `fdinfo` cannot be read, and
    /// [`SysError::Protocol`] when the descriptor is not a pidfd or names
    /// no live pid.
    pub fn validate(fd: OwnedFd) -> Result<Self, SysError> {
        let pid = fdinfo_pid(fd.as_fd())?.ok_or(SysError::Protocol {
            reason: "the pidfd names a reaped process",
        })?;
        // A thread pidfd (`PIDFD_THREAD`, Linux 6.9+, stored as `O_EXCL` in
        // the file flags) polls readable when its one thread exits, while
        // the rest of the process and its mappings live on: never an exit
        // proof.
        let flags = rustix::fs::fcntl_getfl(&fd).map_err(os("fcntl(F_GETFL)"))?;
        if flags.contains(rustix::fs::OFlags::EXCL) {
            return Err(SysError::Protocol {
                reason: "a thread pidfd is not a process exit proof",
            });
        }
        Ok(Self { fd, pid })
    }

    /// The pid it named when validated.
    #[must_use]
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// The descriptor, to pass it.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Whether the process has exited: the pidfd is readable (`poll` with
    /// a zero timeout), which the kernel reports from the exit on, also
    /// while the process is a zombie.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::Os`] when `poll` fails.
    pub fn exited(&self) -> Result<bool, SysError> {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};
        let mut fds = [PollFd::new(&self.fd, PollFlags::IN)];
        let ready = poll(
            &mut fds,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )
        .map_err(os("poll(pidfd)"))?;
        Ok(ready > 0
            && fds
                .iter()
                .any(|fd| fd.revents().intersects(PollFlags::IN | PollFlags::HUP)))
    }
}

/// The pid a pidfd names, from the `Pid:` field of its `fdinfo`: `None`
/// once the process is reaped (the kernel reports `-1`).
fn fdinfo_pid(fd: BorrowedFd<'_>) -> Result<Option<i32>, SysError> {
    use rustix::fd::AsRawFd;
    let path = format!("/proc/self/fdinfo/{}", fd.as_raw_fd());
    let info = std::fs::read_to_string(path).map_err(|error| SysError::Os {
        operation: "read(fdinfo)",
        errno: error.raw_os_error().unwrap_or(0),
    })?;
    let pid = info
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .and_then(|value| value.trim().parse::<i32>().ok())
        .ok_or(SysError::Protocol {
            reason: "not a pidfd",
        })?;
    Ok((pid > 0).then_some(pid))
}

// Miri cannot execute these system calls.
#[cfg(test)]
#[cfg(not(miri))]
mod tests {
    use super::*;
    use rustix::fd::AsRawFd;

    fn record() -> RegionRecord {
        RegionRecord {
            instance: 0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00,
            region: 7,
            kind: RegionKind::LogBuffer,
            generation: 2,
            layout: 1,
            structure_length: 4096,
        }
    }

    fn send_two(socket: BorrowedFd<'_>, pair: [BorrowedFd<'_>; 2]) {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        assert!(control.push(SendAncillaryMessage::ScmRights(&pair)));
        rustix::net::sendmsg(
            socket,
            &[IoSlice::new(b"two")],
            &mut control,
            SendFlags::empty(),
        )
        .unwrap();
    }

    fn pass(region: &Region) -> OwnedFd {
        let (a, b) = seqpacket_pair().unwrap();
        assert_eq!(
            send(a.as_fd(), b"region", region.descriptor()).unwrap(),
            Sent::Sent
        );
        let mut buffer = [0u8; 64];
        let Recv::Message(received) = recv(b.as_fd(), &mut buffer).unwrap() else {
            panic!("no message");
        };
        assert_eq!(&buffer[..received.len], b"region");
        received.fd.unwrap()
    }

    #[test]
    fn a_region_is_created_passed_attached_and_shared() {
        let region = Region::create(record()).unwrap();
        let fd = pass(&region);
        // Received close-on-exec.
        let flags = rustix::io::fcntl_getfd(&fd).unwrap();
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
        let attached = Region::attach(fd, record()).unwrap();
        assert!(attached.descriptor().is_none());
        assert_eq!(attached.structure().len(), 4096 / WORD_BYTES);
        region
            .structure()
            .get(3)
            .unwrap()
            .store(42, Ordering::Release);
        assert_eq!(
            attached.structure().get(3).unwrap().load(Ordering::Acquire),
            42
        );
        attached
            .structure()
            .get(9)
            .unwrap()
            .store(7, Ordering::Release);
        assert_eq!(
            region.structure().get(9).unwrap().load(Ordering::Acquire),
            7
        );
    }

    #[test]
    fn a_region_cannot_be_resized_through_any_descriptor() {
        let region = Region::create(record()).unwrap();
        let fd = region.descriptor().unwrap();
        assert_eq!(rustix::fs::ftruncate(fd, 0), Err(rustix::io::Errno::PERM));
        assert_eq!(
            rustix::fs::ftruncate(fd, 1 << 20),
            Err(rustix::io::Errno::PERM)
        );
        let path = format!("/proc/self/fd/{}", fd.as_raw_fd());
        let reopened = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        assert!(reopened.set_len(0).is_err());
        assert!(reopened.set_len(1 << 20).is_err());
        assert_eq!(
            rustix::fs::fallocate(&reopened, rustix::fs::FallocateFlags::empty(), 0, 1 << 20),
            Err(rustix::io::Errno::PERM)
        );
        // Writing through a reopen succeeds: outside the isolation boundary
        // (ADR-0045, "What this decision does not yet prove").
        assert!(std::os::unix::fs::FileExt::write_at(&reopened, &[1], 200).is_ok());
    }

    #[test]
    fn attach_rejects_wrong_seals_size_header_and_plain_files() {
        // Missing seals: a bare memfd of the right size.
        let bare =
            rustix::fs::memfd_create("bare", MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)
                .unwrap();
        rustix::fs::ftruncate(&bare, (HEADER_STRIDE + 4096) as u64).unwrap();
        assert!(matches!(
            Region::attach(bare, record()),
            Err(SysError::SealMismatch { .. })
        ));
        // Extra seal: a write seal as well.
        let sealed =
            rustix::fs::memfd_create("extra", MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)
                .unwrap();
        rustix::fs::ftruncate(&sealed, (HEADER_STRIDE + 4096) as u64).unwrap();
        rustix::fs::fcntl_add_seals(&sealed, SIZE_SEALS | SealFlags::WRITE).unwrap();
        assert!(matches!(
            Region::attach(sealed, record()),
            Err(SysError::SealMismatch { .. })
        ));
        // Wrong size for the record.
        let region = Region::create(record()).unwrap();
        let larger = RegionRecord {
            structure_length: 8192,
            ..record()
        };
        assert!(matches!(
            Region::attach(pass(&region), larger),
            Err(SysError::InvalidRegion { .. })
        ));
        // Same size and seals, another region: caught by the header.
        for other in [
            RegionRecord {
                region: 8,
                ..record()
            },
            RegionRecord {
                generation: 3,
                ..record()
            },
            RegionRecord {
                kind: RegionKind::Broadcast,
                ..record()
            },
            RegionRecord {
                instance: 1,
                ..record()
            },
            RegionRecord {
                layout: 2,
                ..record()
            },
        ] {
            assert!(matches!(
                Region::attach(pass(&region), other),
                Err(SysError::InvalidRegion { .. })
            ));
        }
        // A plain file cannot carry seals.
        let file = std::fs::File::open("/proc/self/stat").unwrap();
        assert!(Region::attach(OwnedFd::from(file), record()).is_err());
        // Invalid structure lengths.
        for structure_length in [0, 100, 4097] {
            assert!(matches!(
                Region::create(RegionRecord {
                    structure_length,
                    ..record()
                }),
                Err(SysError::InvalidRegion { .. })
            ));
        }
    }

    #[test]
    fn the_transport_accepts_zero_or_one_descriptor_and_rejects_the_rest() {
        let region = Region::create(record()).unwrap();
        let other = Region::create(RegionRecord {
            region: 8,
            ..record()
        })
        .unwrap();
        let (a, b) = seqpacket_pair().unwrap();
        let mut buffer = [0u8; 16];
        // No descriptor.
        assert_eq!(send(a.as_fd(), b"hello", None).unwrap(), Sent::Sent);
        let Recv::Message(plain) = recv(b.as_fd(), &mut buffer).unwrap() else {
            panic!("no message");
        };
        assert_eq!((plain.len, plain.fd.is_none()), (5, true));
        // An empty message is refused before sending.
        assert!(matches!(
            send(a.as_fd(), b"", None),
            Err(SysError::Protocol { .. })
        ));
        // Two descriptors in one message: rejected, both closed.
        send_two(
            a.as_fd(),
            [region.descriptor().unwrap(), other.descriptor().unwrap()],
        );
        assert!(matches!(
            recv(b.as_fd(), &mut buffer),
            Err(SysError::Protocol { .. })
        ));
        // A message longer than the buffer: rejected, its descriptor closed.
        assert_eq!(
            send(a.as_fd(), &[9u8; 64], region.descriptor()).unwrap(),
            Sent::Sent
        );
        assert!(matches!(
            recv(b.as_fd(), &mut buffer),
            Err(SysError::Protocol { .. })
        ));
        // Nothing queued on a non-blocking socket, then the peer closes:
        // two different outcomes.
        rustix::io::ioctl_fionbio(&b, true).unwrap();
        assert!(matches!(
            recv(b.as_fd(), &mut buffer).unwrap(),
            Recv::WouldBlock
        ));
        drop(a);
        for _ in 0..2 {
            assert!(matches!(
                recv(b.as_fd(), &mut buffer).unwrap(),
                Recv::PeerClosed
            ));
        }
    }

    #[test]
    fn a_full_non_blocking_socket_reports_would_block() {
        let (a, _b) = seqpacket_pair().unwrap();
        rustix::io::ioctl_fionbio(&a, true).unwrap();
        let message = [0u8; 4096];
        let mut outcome = Sent::Sent;
        for _ in 0..10_000 {
            outcome = send(a.as_fd(), &message, None).unwrap();
            if outcome == Sent::WouldBlock {
                break;
            }
        }
        assert_eq!(outcome, Sent::WouldBlock);
    }

    #[test]
    fn peer_credentials_name_this_process() {
        let (a, _b) = seqpacket_pair().unwrap();
        let credentials = peer_credentials(a.as_fd()).unwrap();
        assert_eq!(
            credentials.pid.as_raw_nonzero().get().cast_unsigned(),
            std::process::id()
        );
        let owner = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata("/proc/self").unwrap());
        assert_eq!(credentials.uid.as_raw(), owner);
    }

    #[test]
    fn a_pidfd_names_its_process_until_it_exits() {
        let own = PidFd::of_self().unwrap();
        assert_eq!(own.pid(), rustix::process::getpid().as_raw_nonzero().get());
        assert!(!own.exited().unwrap());

        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let child_pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
        let open = || {
            rustix::process::pidfd_open(child_pid, rustix::process::PidfdFlags::empty()).unwrap()
        };
        let pidfd = PidFd::validate(open()).unwrap();
        assert_eq!(pidfd.pid(), child_pid.as_raw_nonzero().get());
        assert!(!pidfd.exited().unwrap());
        child.kill().unwrap();
        // Exited is reported from the exit on, before and after the reap.
        while !pidfd.exited().unwrap() {
            std::thread::yield_now();
        }
        let zombie = open();
        child.wait().unwrap();
        assert!(pidfd.exited().unwrap());
        // A pidfd whose process is reaped is refused at validation.
        assert!(matches!(
            PidFd::validate(zombie),
            Err(SysError::Protocol { .. })
        ));
    }

    #[test]
    fn a_readable_descriptor_that_is_not_a_pidfd_is_refused() {
        // A memfd polls readable: it must never pass as an exited pidfd.
        let region = Region::create(record()).unwrap();
        let fd = region.descriptor().unwrap().try_clone_to_owned().unwrap();
        assert!(matches!(
            PidFd::validate(fd),
            Err(SysError::Protocol { .. })
        ));
    }

    #[test]
    fn a_thread_pidfd_is_refused() {
        // `PIDFD_THREAD` is `O_EXCL` (Linux 6.9+); older kernels refuse the
        // flag at `pidfd_open`, and then there is nothing to validate.
        let thread = rustix::process::PidfdFlags::from_bits_retain(rustix::fs::OFlags::EXCL.bits());
        match rustix::process::pidfd_open(rustix::process::getpid(), thread) {
            Ok(fd) => assert!(matches!(
                PidFd::validate(fd),
                Err(SysError::Protocol { .. })
            )),
            Err(errno) => assert_eq!(errno, rustix::io::Errno::INVAL),
        }
        // A process pidfd of the same process carries no such flag.
        assert!(PidFd::of_self().is_ok());
    }

    fn private_dir() -> std::path::PathBuf {
        use std::os::unix::fs::DirBuilderExt;
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("karyos-ipc-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        dir
    }

    #[test]
    fn a_client_connects_to_the_listening_socket() {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_dir().join("driver");
        let listener = listen(&dir, 8).unwrap();
        assert_eq!(
            std::fs::metadata(dir.join(SOCKET_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(accept(listener.as_fd()).unwrap().is_none());
        let client = connect(&dir, core::time::Duration::from_secs(1)).unwrap();
        let server = accept(listener.as_fd()).unwrap().unwrap();
        assert_eq!(send(client.as_fd(), b"hi", None).unwrap(), Sent::Sent);
        let mut buffer = [0u8; 8];
        assert!(matches!(
            recv(server.as_fd(), &mut buffer).unwrap(),
            Recv::Message(_)
        ));
        // A second driver cannot take a live socket.
        assert!(matches!(listen(&dir, 8), Err(SysError::Protocol { .. })));
        // A stale socket file (no listener) is replaced. Another test that
        // spawns a process can hold a copy of the listener between its fork
        // and exec (close-on-exec acts only at exec), so retry briefly.
        drop(listener);
        let start = std::time::Instant::now();
        let again = loop {
            match listen(&dir, 8) {
                Ok(again) => break again,
                Err(_) if start.elapsed() < core::time::Duration::from_secs(2) => {
                    std::thread::yield_now();
                }
                Err(error) => panic!("{error:?}"),
            }
        };
        drop(connect(&dir, core::time::Duration::from_secs(1)).unwrap());
        assert!(accept(again.as_fd()).unwrap().is_some());
    }

    #[test]
    fn modes_and_owners_are_checked() {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_dir();
        let listener = listen(&dir, 8).unwrap();
        let socket = dir.join(SOCKET_NAME);
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            connect(&dir, core::time::Duration::from_secs(1)),
            Err(SysError::Protocol { .. })
        ));
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            connect(&dir, core::time::Duration::from_secs(1)),
            Err(SysError::Protocol { .. })
        ));
        drop(listener);
        assert!(matches!(listen(&dir, 8), Err(SysError::Protocol { .. })));
    }

    #[test]
    fn listen_never_replaces_what_is_not_a_driver_socket() {
        let dir = private_dir();
        let path = dir.join(SOCKET_NAME);
        std::fs::write(&path, b"not a socket").unwrap();
        assert!(matches!(listen(&dir, 8), Err(SysError::Protocol { .. })));
        assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
    }

    #[test]
    fn a_full_backlog_bounds_connect_and_the_start_probe() {
        let dir = private_dir();
        let listener = listen(&dir, 0).unwrap();
        let timeout = core::time::Duration::from_millis(100);
        // Never accepted: the backlog fills, then connect gives up in time.
        let mut held = Vec::new();
        let start = std::time::Instant::now();
        loop {
            match connect(&dir, timeout) {
                Ok(socket) => held.push(socket),
                Err(_) => break,
            }
            assert!(held.len() < 64, "the backlog never filled");
        }
        assert!(start.elapsed() < core::time::Duration::from_secs(5));
        // A second driver's start probe answers at once.
        let probe = std::time::Instant::now();
        assert!(matches!(listen(&dir, 8), Err(SysError::Protocol { .. })));
        assert!(probe.elapsed() < core::time::Duration::from_secs(1));
        drop(listener);
    }
}
