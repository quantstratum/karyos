// SPDX-License-Identifier: Apache-2.0

//! The thread rules of the handles (`include/karyos.h`, "Threads";
//! quantstratum-docs: karyos/design/embedded-api.md, "Requirements for the
//! C ABI"), checked at compile time.
//!
//! No handle has thread affinity: its object sits in a slot of a static
//! [`Table`], so it must move to whichever thread calls next (`Send`), and
//! the table is shared by every thread (`Sync`); the slot's `try_lock`
//! turns a concurrent call into `KARYOS_E_BUSY`. A field that is not
//! `Send` fails here, by the kind's name, not inside a `OnceLock`.

use crate::api::{archive, client, conflated, driver, publication, subscription};
use crate::handles::{Handle, Table};

/// Compiles only for a `T` that may move to another thread.
const fn sendable<T: Send>() {}

/// Compiles only for a `T` that threads may share.
const fn shareable<T: Sync>() {}

/// Each kind's object moves between threads, and its table is shared.
const _: () = {
    sendable::<driver::Driver>();
    shareable::<Table<driver::Driver>>();
    sendable::<client::ClientEntry>();
    shareable::<Table<client::ClientEntry>>();
    sendable::<publication::Entry>();
    shareable::<Table<publication::Entry>>();
    // A claim's slot names its publication.
    sendable::<Handle>();
    shareable::<Table<Handle>>();
    sendable::<subscription::Entry>();
    shareable::<Table<subscription::Entry>>();
    sendable::<conflated::Entry>();
    shareable::<Table<conflated::Entry>>();
    sendable::<archive::Entry>();
    shareable::<Table<archive::Entry>>();
};
