// SPDX-License-Identifier: Apache-2.0

//! C5 version 2's frozen W2 in-flight byte case, from the library
//! (`karyos_raft_eval::v2`), where the node and client processes of a
//! real-process run take it too; shared by its oracle
//! (`tests/w2_bytes.rs`), the corpus runner (`tests/corpus.rs`) and the
//! real-process runs, so all run the very same case.

pub use karyos_raft_eval::v2::*;
