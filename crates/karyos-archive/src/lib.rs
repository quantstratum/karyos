// SPDX-License-Identifier: Apache-2.0

//! Recording, catalog, replay and recording groups (quantstratum-docs:
//! karyos/SPEC.md §8; karyos/design/archive-gap-analysis.md).
//!
//! Built so far: the CRC-32C and the segment store of one recording (A2).
//! The catalog, the recorder, replay and recording groups follow.

#![forbid(unsafe_code)]

pub mod crc32c;
pub mod segment;
