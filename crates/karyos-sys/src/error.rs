// SPDX-License-Identifier: Apache-2.0

//! Errors of the `karyos-sys` crate.

use thiserror::Error;

/// Errors raised by the term identity, slot descriptor and loan protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SysError {
    /// A term count reached the `2^31` limit of a publication incarnation.
    #[error("term count {count} reached the limit of 2^31; close the incarnation")]
    MaxPositionExceeded {
        /// The term count that could not be produced.
        count: u64,
    },
    /// A term count value is outside `0..2^31`.
    #[error("term count {value} is outside 0..2^31")]
    InvalidTermCount {
        /// The rejected value.
        value: u32,
    },
    /// A mapping generation value does not fit in 24 bits.
    #[error("generation {value} does not fit in 24 bits")]
    InvalidGeneration {
        /// The rejected value.
        value: u32,
    },
    /// The next mapping generation would need `2^24`.
    #[error("generation {generation} is the last one; close the incarnation")]
    GenerationExhausted {
        /// The current, final generation.
        generation: u32,
    },
    /// A slot index is outside `0..128`.
    #[error("slot index {value} is outside 0..128")]
    InvalidSlotIndex {
        /// The rejected value.
        value: u8,
    },
    /// A descriptor has state 0, which marks an uninitialised mapping.
    #[error("descriptor {raw:#018x} is uninitialised")]
    UninitialisedDescriptor {
        /// The raw descriptor word.
        raw: u64,
    },
    /// A descriptor carries a state code that is not defined.
    #[error("descriptor {raw:#018x} has unknown state {state}")]
    UnknownSlotState {
        /// The raw descriptor word.
        raw: u64,
        /// The state byte.
        state: u8,
    },
    /// A non-zero loan word lacks its valid flag.
    #[error("loan word {raw:#018x} is non-zero without the valid flag")]
    InvalidLoanWord {
        /// The raw loan word.
        raw: u64,
    },
    /// A descriptor belongs to a different mapping generation than expected.
    #[error("descriptor generation {found} does not match mapping generation {expected}")]
    GenerationMismatch {
        /// The generation of the mapping being used.
        expected: u32,
        /// The generation found in the descriptor.
        found: u32,
    },
    /// A transition was called with a descriptor in the wrong state; the
    /// atomic descriptor was not read or changed.
    #[error("transition requires a descriptor in state {required} but was given state {given}")]
    WrongSourceState {
        /// The state code the transition requires.
        required: u8,
        /// The state code of the descriptor passed in.
        given: u8,
    },
    /// A memory region failed validation (null, misaligned, empty, not a
    /// multiple of the word or page size, or larger than `isize::MAX`).
    #[error("invalid memory region at {address:#x} of {len} bytes")]
    InvalidRegion {
        /// Base address, or 0 before mapping.
        address: usize,
        /// Length in bytes.
        len: usize,
    },
    /// A system call failed.
    #[error("{operation} failed with OS error {errno}")]
    Os {
        /// The failing operation.
        operation: &'static str,
        /// Raw OS error number.
        errno: i32,
    },
    /// A state transition found the descriptor in an unexpected state.
    #[error("descriptor transition expected {expected:#018x} but found {found:#018x}")]
    UnexpectedDescriptor {
        /// The descriptor the transition required.
        expected: u64,
        /// The descriptor actually found.
        found: u64,
    },
}
