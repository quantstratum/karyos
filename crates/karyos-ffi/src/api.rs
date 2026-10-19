// SPDX-License-Identifier: Apache-2.0

//! The safe implementations behind `abi`: each takes checked Rust values
//! and answers a handle, a value or a [`Failure`](crate::status::Failure).

pub(crate) mod client;
