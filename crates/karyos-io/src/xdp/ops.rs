// SPDX-License-Identifier: Apache-2.0

//! The [`XskOps`] seam of the AF_XDP copy-mode backend (`quantstratum-docs:
//! karyos/design/af-xdp-backend.md` section 2): the only way the endpoint
//! of [`super::endpoint`] reaches a socket's UMEM and rings.
//!
//! The seam owns the UMEM and enforces frame ownership (design 6.3), so the
//! rule "no frame is touched while the kernel owns it" holds there, not in
//! the endpoint:
//!
//! - TX frames `0..T` are the endpoint's until [`XskOps::push_tx`] puts
//!   one in the TX ring; then the kernel's until a completion names its
//!   address. Only a completion naming a frame the kernel owns
//!   ([`Completion::Released`]) gives it back: any other address is
//!   reported [`Completion::Invalid`] and changes nothing.
//! - RX frames `T..T + R` are Posted (in the fill ring, the kernel's) until
//!   an RX descriptor names them; then [`XskOps::lend_rx`] lends the bytes
//!   and reposts the frame when the lend returns or unwinds.

#![forbid(unsafe_code)]

/// One RX descriptor as the RX ring holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxDesc {
    /// The UMEM address of the first byte.
    pub addr: u64,
    /// The bytes written.
    pub len: u32,
}

impl RxDesc {
    /// An empty descriptor for the stack arrays `reap_rx` fills.
    pub const EMPTY: Self = Self { addr: 0, len: 0 };
}

/// One completion ring entry, classified by the seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    /// The address of TX frame `frame`, which the kernel owned: it is the
    /// endpoint's again.
    Released {
        /// The TX frame index.
        frame: u16,
    },
    /// An address that names no kernel owned TX frame (out of range, not
    /// frame aligned, an RX frame, or a frame already released): nothing
    /// was released.
    Invalid {
        /// The address read.
        addr: u64,
    },
}

impl Completion {
    /// An empty entry for the stack arrays `reap_completions` fills.
    pub const EMPTY: Self = Self::Invalid { addr: u64::MAX };
}

/// A raw OS error number of a socket call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

/// The UMEM and rings of one AF_XDP socket in copy mode.
pub trait XskOps {
    /// Bytes of each UMEM frame (`F`).
    fn frame_len(&self) -> u32;

    /// TX frames (`T`).
    fn tx_frames(&self) -> u16;

    /// RX frames (`R`).
    fn rx_frames(&self) -> u32;

    /// The bytes of TX frame `frame`, or `None` while the kernel owns it.
    fn tx_frame_mut(&mut self, frame: u16) -> Option<&mut [u8]>;

    /// Free TX ring entries now.
    fn tx_free(&mut self) -> u32;

    /// Writes the descriptor of the first `len` bytes of TX frame `frame`
    /// into the TX ring, invisible to the kernel until
    /// [`XskOps::publish_tx`]. The frame is kernel owned from here.
    ///
    /// # Errors
    ///
    /// `false`: the ring is full, the frame is kernel owned or out of
    /// range; nothing was written.
    fn push_tx(&mut self, frame: u16, len: u32) -> bool;

    /// The Release store of the TX producer: the exposure point (7.3).
    fn publish_tx(&mut self);

    /// Whether the TX ring asks for a kick (`XDP_RING_NEED_WAKEUP`), read
    /// after the producer store.
    fn tx_needs_wakeup(&mut self) -> bool;

    /// One nonblocking kick: `sendto(fd, NULL, 0, MSG_DONTWAIT)`.
    ///
    /// # Errors
    ///
    /// The errno (7.4).
    fn kick_tx(&mut self) -> Result<(), Errno>;

    /// Reads up to `out.len()` completion entries and stores the consumer
    /// once; returns how many.
    fn reap_completions(&mut self, out: &mut [Completion]) -> usize;

    /// Reads up to `out.len()` RX descriptors and stores the consumer once.
    /// A descriptor inside one Posted RX frame moves that frame to
    /// Completed; any other descriptor is returned as it is and changes
    /// nothing.
    fn reap_rx(&mut self, out: &mut [RxDesc]) -> usize;

    /// Lends the bytes of `desc`, which must lie inside one Completed RX
    /// frame, to `lend`, and reposts the frame to the fill ring when
    /// `lend` returns or unwinds. `None`, calling nothing, otherwise.
    fn lend_rx<T>(&mut self, desc: RxDesc, lend: impl FnOnce(&[u8]) -> T) -> Option<T>;

    /// The Release store of the fill producer, once per poll.
    fn publish_fill(&mut self);

    /// Whether the fill ring asks for a wakeup, read after its producer
    /// store.
    fn fill_needs_wakeup(&mut self) -> bool;

    /// One nonblocking RX wakeup: `recvfrom(fd, NULL, 0, MSG_DONTWAIT)`.
    ///
    /// # Errors
    ///
    /// The errno.
    fn kick_rx(&mut self) -> Result<(), Errno>;

    /// TX frames the kernel owns now.
    fn tx_kernel_owned(&self) -> u16;

    /// RX frames Posted now.
    fn rx_posted(&self) -> u32;
}
