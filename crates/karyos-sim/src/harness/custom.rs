// SPDX-License-Identifier: Apache-2.0

//! The custom Raft core (ADR-0105) behind [`super::core::ConsensusCore`]:
//! `karyos_cluster::custom`, re-exported here, so the harness runs the same
//! adapter the shipped node does (C6, quantstratum/karyos#681).

pub use karyos_cluster::custom::*;
