// SPDX-License-Identifier: Apache-2.0

//! The bounded record journal of `karyos-sys` (SPEC.md §7.3, design in
//! `quantstratum-docs: karyos/design/record-journal.md`), re-exported for crates that depend on
//! `karyos-protocol` only, such as `karyos-trace`.

pub use karyos_sys::record_journal::{
    Append, DropRange, JournalConsumer, JournalError, JournalLayout, JournalWriter, Losses, Record,
    Stamp, Taken, record_journal,
};
