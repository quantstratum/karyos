// SPDX-License-Identifier: Apache-2.0

//! Recording, catalog, replay and recording groups (quantstratum-docs:
//! karyos/SPEC.md §8; karyos/design/archive-gap-analysis.md).
//!
//! Built so far: the CRC-32C, the segment store of one recording (A2), the
//! catalog of an archive directory (A3), the recorder and replay, and the
//! records of a recording group's journal (A7a). The rest of recording
//! groups follows.

#![forbid(unsafe_code)]

pub mod agent;
pub mod catalog;
pub mod control;
pub mod crc32c;
pub mod disk;
#[cfg(test)]
mod fault;
pub mod group;
pub mod recorder;
pub mod segment;

pub use segment::replay;
pub mod source;
