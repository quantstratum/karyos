// SPDX-License-Identifier: Apache-2.0

//! Trace context, bounded journals, clock calibration and HDR aggregation
//! (the planned scope from `quantstratum-docs: karyos/SPEC.md` §14).
//!
//! Implemented so far: the trace observation record (`record`) and a typed
//! trace journal over the bounded record journal (`journal`), as designed in
//! `quantstratum-docs: karyos/design/trace-records.md`; loss attribution to traces in one journal
//! (`attribution`), as designed in `quantstratum-docs: karyos/design/trace-attribution.md`; and
//! the sampling policy (`sampling`), as designed in
//! `quantstratum-docs: karyos/design/trace-sampling.md`; and the report
//! (`report`) over journal sources (`source`), the in-process collector or
//! a tool's reader of the driver's trace mirror, as designed in
//! `quantstratum-docs: karyos/design/trace-tool.md`. Seals for long-running
//! journals, clock calibration and histograms do not exist yet.
//!
//! # Support
//!
//! Published to crates.io for its first consumer, the analysis engine of
//! karyos-insights (ADR-0068, INS-Q4; karyos#997). Its public analysis
//! surface is **supported in alpha**, on the same terms as the `karyos`
//! facade, `karyos-client` and `karyos-archive` (alpha releases may still
//! break it, and say so in their release notes):
//!
//! - the report: [`report`], with [`TraceReport`], [`TraceAnswer`],
//!   [`PublicationSummary`], [`PublicationKey`], [`JournalClock`],
//!   [`JournalId`], [`HeldMessage`] and [`HistogramConfig`];
//! - journal sources: [`source`], with the [`JournalSource`] contract,
//!   [`SourceState`] and [`SourceLosses`];
//! - histograms: [`histogram`], with [`Histogram`], [`HistogramCounts`],
//!   [`SideCounts`], [`Quantile`] and [`HistogramError`];
//! - clock calibration: [`clocks`], with [`Calibration`], [`latency`],
//!   [`Latency`], [`ClockKey`], [`Observation`], [`CalibrationError`] and
//!   [`Unavailable`];
//! - and the types those signatures name: [`TraceError`], [`Verdict`],
//!   [`AttributionConfig`], [`ClockProvenance`], [`Collected`],
//!   [`ObserverId`] and the record types of [`record`] a source yields.
//!
//! Everything else is internal and unstable in alpha, with no
//! compatibility promise: the writers, collectors and journals
//! ([`journal`]), the trace agents ([`agent`], [`network_agent`]),
//! sampling ([`sampling`]), id sources ([`ids`]), trace clocks
//! ([`trace_clock`]) and the attributor's own state ([`attribution`]
//! beyond [`Verdict`] and [`AttributionConfig`]). The C ABI of
//! `karyos-ffi` keeps its own `0.y.z` rule.

pub mod agent;
pub mod attribution;
pub mod clocks;
pub mod error;
pub mod histogram;
pub mod ids;
pub mod journal;
pub mod network_agent;
pub mod record;
pub mod report;
pub mod sampling;
pub mod source;
pub mod trace_clock;

pub use agent::{AgentCounter, AgentCounts, TraceAgent};
pub use attribution::{AttributionConfig, Attributor, HeldRange, Observed, Verdict, combine};
pub use clocks::{
    Calibration, CalibrationError, ClockKey, Latency, Observation, Unavailable, latency,
};
pub use error::TraceError;
pub use histogram::{Histogram, HistogramCounts, HistogramError, Quantile, SideCounts};
pub use ids::{BufferedIds, OsRandom, RandomSource};
pub use journal::{
    ApplicationContext, ApplicationPoint, Collected, ObserverId, TraceCollector, TraceWriter,
    trace_journal, trace_writer,
};
pub use network_agent::{NetworkCounter, NetworkCounts, NetworkTraceAgent};
pub use record::{
    MAX_LANE, MAX_METADATA, Metadata, NetworkPath, OBSERVATION_WORDS, ObservedTime, PacketId,
    Point, PublicationId, RECORD_VERSION, RECORD_VERSION_1, RECORD_VERSION_2, RECORD_VERSION_4,
    RECORD_WORDS, SubscriberId, TraceIds, TraceRecord, Value, decode_record, encode_record,
};
pub use report::{
    HeldMessage, HistogramConfig, JournalClock, JournalId, PublicationKey, PublicationSummary,
    TraceAnswer, TraceReport,
};
pub use sampling::{Decision, IdSource, Sampler, Sampling};
pub use source::{JournalSource, SourceLosses, SourceState};
pub use trace_clock::{ClockProvenance, HostMonotonicClock, MonotonicClock, TraceClock};
