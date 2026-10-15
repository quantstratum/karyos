// SPDX-License-Identifier: Apache-2.0

//! Shared memory mappings, `AtomicBuffer`, rings, broadcast buffer, counters,
//! seqlock slots, TSC and NUMA placement.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14. Implemented so far: the
//! term identity types, the slot descriptor and loan word encodings, and the
//! loan, revocation and reclaim handshakes of SPEC.md §4; the decision word,
//! frame types and fragment geometry (`frame`, `sizing`); atomic-only views
//! of memory (`atomic_view`), with a heap backing; and, on Linux, a
//! size-sealed `memfd` mapping viewed only as atomic words (`mmap`). Term byte
//! access exists in `term_memory` (one heap term, never reused) and in
//! `log_buffer` (one lane in heap memory with exclusive publication, loans,
//! rotation, reclamation, cleaning and reuse, for the embedded mode).
//! Attaching to another process's mapping does not exist yet.
//!
//! The `loan` functions are raw protocol helpers over atomics. They do not
//! enforce who owns a loan word, which lane bank a slot belongs to, that a
//! scan covers every participant, or that only the driver performs driver
//! steps. The future capability types that hand out payload references must
//! enforce those properties; these helpers alone are not that capability.

#[cfg(feature = "test-hooks")]
pub mod alloc_count;
pub mod atomic_view;
pub mod broadcast;
#[cfg(not(loom))]
mod cnc_store;
pub mod command_ring;
pub mod conflation;
pub mod counters;
// The typed rings over `diag_ring`; loom models `diag_ring` itself.
#[cfg(not(loom))]
pub mod diag;
pub mod diag_ring;
pub mod error;
pub mod frame;
pub mod host_clock;
pub mod loan;
pub mod participant;
// Real memory with std atomics, like `term_memory`.
#[cfg(not(loom))]
#[cfg(target_os = "linux")]
pub mod ipc;
#[cfg(not(loom))]
pub mod log_buffer;
#[cfg(target_os = "linux")]
pub mod mmap;
pub mod publication;
pub mod random;
// Used only by `log_buffer`, which Loom builds leave out.
#[cfg(not(loom))]
pub mod receive;
pub mod record_journal;
pub mod registration;
pub mod sizing;
pub mod slot;
pub mod sync;
pub mod term;
#[cfg(not(loom))]
pub mod term_bytes;
// Real memory with std atomics; the Loom model covers `publication` instead.
#[cfg(not(loom))]
pub mod term_memory;
// Pause points for multi-process tests (feature `test-hooks`).
#[cfg(all(feature = "test-hooks", not(loom)))]
pub mod test_pause;

pub use error::{LayoutError, SysError};
