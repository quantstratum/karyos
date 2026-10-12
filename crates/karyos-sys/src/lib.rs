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
//! access exists only in `term_memory`: one heap term, never reused, with one
//! exclusive writer and concurrent readers in one process. Loans over term
//! bytes, rotation, cleaning and attaching to another process's mapping do
//! not exist yet.
//!
//! The `loan` functions are raw protocol helpers over atomics. They do not
//! enforce who owns a loan word, which lane bank a slot belongs to, that a
//! scan covers every participant, or that only the driver performs driver
//! steps. The future capability types that hand out payload references must
//! enforce those properties; these helpers alone are not that capability.

pub mod atomic_view;
pub mod error;
pub mod frame;
pub mod loan;
#[cfg(target_os = "linux")]
pub mod mmap;
pub mod sizing;
pub mod slot;
pub mod sync;
pub mod term;
pub mod term_memory;

pub use error::{LayoutError, SysError};
