// SPDX-License-Identifier: Apache-2.0

//! The optional `io_uring` datagram backend (`quantstratum-docs:
//! karyos/design/io-uring-backend.md`; SPEC.md §16.4), behind the `uring`
//! feature on Linux.
//!
//! Implemented so far: the RX half ([`rx::UringRx`]) with one multishot
//! `RECVMSG` over a provided buffer ring, re-registered at reset; the TX
//! half ([`tx::UringTx`]) with copied
//! `IORING_OP_SENDMSG`, SQPOLL off unless configured, per-queue and
//! whole-ring cancellation, a bounded reset that retains whatever the
//! kernel still owns and reports it, over the [`ops::RingOps`] seam; the
//! real ring over the admitted `io-uring` crate (`ring`, Linux and feature
//! `uring` only) with its send parking probe; and the scripted double
//! (`scripted`); and the explicit `io_uring_or_sockets` selection
//! ([`select`]).
//!
//! `unsafe` is denied here and allowed in `ring` alone (SPEC.md §14,
//! choice IU-9).

#![deny(unsafe_code)]

pub mod ops;
#[cfg(all(feature = "uring", target_os = "linux"))]
#[expect(
    unsafe_code,
    reason = "the SQE pushes of the admitted io-uring crate (SPEC.md §14, IU-9)"
)]
pub mod ring;
pub mod rx;
#[cfg(any(test, feature = "test-hooks"))]
pub mod scripted;
pub mod select;
pub mod tx;
