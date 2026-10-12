// SPDX-License-Identifier: Apache-2.0

//! Shared memory mappings, `AtomicBuffer`, rings, broadcast buffer, counters,
//! seqlock slots, TSC and NUMA placement.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14. Implemented so far: the
//! term identity types, the slot descriptor and loan word encodings, and the
//! loan, revocation and reclaim handshakes of SPEC.md §4. Mappings and payload
//! access do not exist yet; nothing here grants access to term bytes.

pub mod error;
pub mod loan;
pub mod slot;
pub mod sync;
pub mod term;

pub use error::SysError;
