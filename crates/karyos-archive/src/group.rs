// SPDX-License-Identifier: Apache-2.0

//! Recording groups (quantstratum-docs: karyos/SPEC.md §8.3; ADR-0024;
//! karyos/design/archive-gap-analysis.md, A7 and A9).
//!
//! Built so far: the journal's records, schema 3 version 1 ([`record`]),
//! and the order rules a journal obeys ([`order`]), from
//! `quantstratum-docs: karyos/design/recording-group-records.md` (A7a);
//! the journal on disk ([`journal`], A7b); its three prefixes
//! ([`prefix`], A7c); the first part of their replay ([`replay`], A8).
//! The Gateway and checkpoints follow.

pub mod journal;
pub mod order;
pub mod prefix;
pub mod record;
pub mod replay;
