// SPDX-License-Identifier: Apache-2.0

//! Trace context, bounded journals, clock calibration and HDR aggregation
//! (the planned scope from `quantstratum-docs: karyos/SPEC.md` §14).
//!
//! Implemented so far: the trace observation record (`record`) and a typed
//! trace journal over the bounded record journal (`journal`), as designed in
//! `quantstratum-docs: karyos/design/trace-records.md`; loss attribution to traces in one journal
//! (`attribution`), as designed in `quantstratum-docs: karyos/design/trace-attribution.md`; and
//! the sampling policy (`sampling`), as designed in
//! `quantstratum-docs: karyos/design/trace-sampling.md`. Seals for long-running journals, clock
//! calibration and histograms do not exist yet.

pub mod agent;
pub mod attribution;
pub mod clocks;
pub mod error;
pub mod histogram;
pub mod ids;
pub mod journal;
pub mod record;
pub mod sampling;
pub mod trace_clock;

pub use agent::{AgentCounter, AgentCounts, TraceAgent};
pub use attribution::{AttributionConfig, Attributor, Observed, Verdict, combine};
pub use clocks::{
    Calibration, CalibrationError, ClockKey, Latency, Observation, Unavailable, latency,
};
pub use error::TraceError;
pub use histogram::{Histogram, HistogramError, Quantile};
pub use ids::{BufferedIds, OsRandom, RandomSource};
pub use journal::{Collected, ObserverId, TraceCollector, TraceWriter, trace_journal};
pub use record::{
    MAX_LANE, OBSERVATION_WORDS, ObservedTime, PacketId, Point, PublicationId, RECORD_VERSION,
    RECORD_WORDS, SubscriberId, TraceIds, TraceRecord, decode_record, encode_record,
};
pub use sampling::{Decision, IdSource, Sampler, Sampling};
pub use trace_clock::{ClockProvenance, MonotonicClock, TraceClock};
