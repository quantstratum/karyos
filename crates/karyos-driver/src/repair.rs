// SPDX-License-Identifier: Apache-2.0

//! The sender's side of reliable repair (`quantstratum-docs:
//! karyos/design/reliable-transport.md`; phase 6, R4, R5 and R7; ACS
//! 15597 and 15701), as standalone components the sender agent wires.
//!
//! - [`admission`] (R4): a NAK's admission, steps 1 to 5 of the eight, and
//!   the ERR NAK_REPLY linger. A NAK that passes goes to the job table
//!   (R5), which applies steps 6 and 7; step 8 runs when the job is first
//!   served (R7).
//! - [`jobs`] (R5): the job table, with exact-interval coalescing, the
//!   repair linger and capacity: steps 6 and 7.
//! - [`scheduler`] (R7): the repair DRR over the lanes within the repair
//!   budget, with step 8 and the end proof at each head.

pub mod absorb;
pub mod admission;
pub mod draw;
pub mod jobs;
pub mod loss;
pub mod scheduler;
