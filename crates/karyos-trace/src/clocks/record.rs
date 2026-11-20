// SPDX-License-Identifier: Apache-2.0

//! The records of a calibration journal, told apart by word 0's low byte
//! (ADR-0090; quantstratum-docs: karyos/design/trace-clocks.md, "UTC
//! reference records"; quantstratum/karyos#1065): 1 a [`Calibration`], 2 a
//! [`UtcReference`]. A reader skips a type it does not know, and never
//! reads one type as another.

use super::utc::{UTC_REFERENCE_TYPE, UtcReference, UtcReferenceError};
use super::{CALIBRATION_VERSION, CALIBRATION_WORDS, Calibration, CalibrationError};

#[cfg(test)]
mod tests;

/// One record of a calibration journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClockRecord {
    /// A calibration between two clocks (type 1).
    Calibration(Calibration),
    /// A clock's UTC reference (type 2).
    UtcReference(UtcReference),
    /// A record type this build does not know: skipped, never misread.
    Unknown {
        /// Word 0's low byte.
        record_type: u8,
    },
}

/// Why a record of a known type is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClockRecordError {
    /// A malformed calibration.
    #[error(transparent)]
    Calibration(#[from] CalibrationError),
    /// A malformed UTC reference record.
    #[error(transparent)]
    UtcReference(#[from] UtcReferenceError),
}

impl ClockRecord {
    /// Decodes one record by its type.
    ///
    /// # Errors
    ///
    /// The type's own refusal: a calibration whose word 0 is not exactly
    /// 1, or any [`UtcReferenceError`].
    pub fn decode(words: &[u64; CALIBRATION_WORDS]) -> Result<Self, ClockRecordError> {
        let [word0, ..] = *words;
        let [record_type, ..] = word0.to_le_bytes();
        match u64::from(record_type) {
            CALIBRATION_VERSION => Ok(Self::Calibration(Calibration::decode(words)?)),
            UTC_REFERENCE_TYPE => Ok(Self::UtcReference(UtcReference::decode(words)?)),
            _ => Ok(Self::Unknown { record_type }),
        }
    }

    /// Decodes every whole record of `words`, a journal's records end to
    /// end, keeping the known ones and counting the skipped ones.
    ///
    /// # Errors
    ///
    /// The first known record that is refused, with its index.
    pub fn decode_all(
        words: &[[u64; CALIBRATION_WORDS]],
    ) -> Result<(Vec<Self>, usize), (usize, ClockRecordError)> {
        let mut records = Vec::with_capacity(words.len());
        let mut skipped = 0usize;
        for (index, record) in words.iter().enumerate() {
            match Self::decode(record).map_err(|error| (index, error))? {
                Self::Unknown { .. } => skipped = skipped.saturating_add(1),
                known => records.push(known),
            }
        }
        Ok((records, skipped))
    }
}
