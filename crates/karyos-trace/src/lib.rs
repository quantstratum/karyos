// SPDX-License-Identifier: Apache-2.0

//! Trace context, bounded journals, clock calibration and HDR aggregation
//! (the planned scope from `quantstratum-docs: karyos/SPEC.md` §14).
//!
//! Implemented so far: the trace observation record (`record`) and a typed
//! trace journal over the bounded record journal (`journal`), as designed in
//! `quantstratum-docs: karyos/design/trace-records.md`. Loss attribution, clock calibration,
//! sampling and histograms do not exist yet.

pub mod attribution;
pub mod error;
pub mod journal;
pub mod record;

pub use attribution::{AttributionConfig, Attributor, Observed, Verdict, combine};
pub use error::TraceError;
pub use journal::{Collected, ObserverId, TraceCollector, TraceWriter, trace_journal};
pub use record::{
    MAX_LANE, OBSERVATION_WORDS, ObservedTime, PacketId, Point, PublicationId, RECORD_VERSION,
    RECORD_WORDS, SubscriberId, TraceIds, TraceRecord, decode_record, encode_record,
};
