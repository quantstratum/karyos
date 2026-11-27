// SPDX-License-Identifier: Apache-2.0

//! The consensus core a harness node drives, and the one driver that
//! orders its persistence: `karyos_cluster::driver`, re-exported here so
//! the harness, its candidates and fixtures, and the shipped node share
//! one interface (C6, quantstratum/karyos#681). The run seed a harness run sets
//! (`RunSeed`) is the driver's too.

pub use karyos_cluster::driver::*;
