// SPDX-License-Identifier: Apache-2.0

//! Atomic types used by the protocol code: `std` atomics normally, Loom's
//! model-checked atomics when built with `--cfg loom`.

#[cfg(loom)]
pub use loom::sync::atomic::{AtomicU64, Ordering, fence};
#[cfg(not(loom))]
pub use std::sync::atomic::{AtomicU64, Ordering, fence};
