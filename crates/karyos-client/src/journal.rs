// SPDX-License-Identifier: Apache-2.0

//! Trace journals the driver creates for a client (`quantstratum-docs:
//! karyos/design/trace-journal-region.md`, J2 and J3).
//!
//! A client asks for a journal with
//! [`ClientConductor::trace_journal`](crate::ClientConductor::trace_journal)
//! once it has built its trace agent. The driver creates the journal,
//! drains it into its trace mirror and answers with the journal number and
//! a hand-over key. An in-process client completes as
//! [`Outcome::Journal`](crate::Outcome::Journal) with the journal's writer
//! over the driver's heap block; a remote client completes as
//! [`Outcome::FetchableJournal`](crate::Outcome::FetchableJournal) and
//! fetches the journal region like a log buffer grant
//! (`RemoteClient::take_journal`), getting a writer over the region it
//! mapped. Either writer appends with the record journal's protocol, so a
//! `karyos-trace` `TraceWriter` runs over it unchanged.
//!
//! Before closing the journal, the client gives the driver its final
//! delivery boundary with
//! [`ClientConductor::close_journal`](crate::ClientConductor::close_journal);
//! dropping the writer closes the journal, and the driver marks it closed
//! once it has drained it to its end.

use karyos_sys::record_journal::{JournalLayout, JournalWriter};

/// A trace journal the driver created for this client: its number, never
/// reused within the driver instance, and its only writer.
#[derive(Debug)]
pub struct ClientJournal {
    journal: u64,
    writer: JournalWriter,
}

impl ClientJournal {
    pub(crate) fn new(journal: u64, writer: JournalWriter) -> Self {
        Self { journal, writer }
    }

    /// The journal number the driver assigned.
    #[must_use]
    pub fn journal(&self) -> u64 {
        self.journal
    }

    /// The journal's writer.
    pub fn writer(&mut self) -> &mut JournalWriter {
        &mut self.writer
    }

    /// The journal number and the writer, for a `TraceWriter`. Dropping the
    /// writer closes the journal.
    #[must_use]
    pub fn into_parts(self) -> (u64, JournalWriter) {
        (self.journal, self.writer)
    }
}

/// A remote client's journal, ready to fetch with `RemoteClient::take_journal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchableJournal {
    /// The journal number the driver assigned.
    pub journal: u64,
    /// The hand-over key of the response, which the fetch names.
    pub key: u64,
    /// The sizes requested, which the fetched region must hold.
    pub layout: JournalLayout,
}
