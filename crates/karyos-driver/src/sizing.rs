// SPDX-License-Identifier: Apache-2.0

//! A sizing report of a driver in IPC mode (Linux; R-CORE-34): the bytes of
//! every shared region the driver and its clients map, computed from the
//! configuration alone, with no driver running.
//!
//! Every figure comes from the same function that sizes the region when it
//! is created (`karyos_sys::sizing::region_length` over each kind's
//! structure length), so the report states the size each region is mapped
//! with, and every line names the configuration inputs it read.
//!
//! The report gives three figures:
//!
//! - **configured**: the fixed regions, `max_clients` command rings, the
//!   trace journal budgets and the streams the host declares;
//! - **bounded**: configured plus the streams clients may still add, up to
//!   `max_streams`, each at the largest declared stream's size;
//! - **restart peak**: bounded plus, for every stream, its
//!   `max_retained_generations` predecessor mappings, which a cutover or a
//!   restart keeps mapped for readers that have not finished. The peak is
//!   never below bounded, and bounded never below configured.
//!
//! **What the cgroup counts.** Every region is a `memfd`, shared by the
//! driver and the clients that map it. A shared page is charged once, to
//! the memory cgroup of the process that first touches it, however many
//! processes map it. In a pod whose processes share one cgroup, each region
//! counts once. The figures are mapped bytes, a ceiling: a page never
//! touched is never charged.

use core::fmt;

use karyos_sys::log_buffer::LogBuffer;
use karyos_sys::sizing::region_length;
use karyos_sys::term_bytes::SharedTerms;

use crate::embedded::{DriverConfig, StreamConfig};

/// What the report does not cover.
pub const EXCLUDED: [&str; 6] = [
    "the application's and karyosd's own heap, code and thread stacks",
    "kernel socket buffers and network receive buffers",
    "the Archive's page cache and recording files",
    "page tables and other kernel memory",
    "the network image lanes and network publications, sized by remote senders and URIs, not by this configuration",
    "the outcome rings and consumed cells of guarded handles, one pair per handle a client takes",
];

/// One line of the report: a kind of region, how many, and the
/// configuration inputs it read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SizingLine {
    /// What the regions hold.
    pub region: String,
    /// How many.
    pub count: u64,
    /// Bytes of each, header included.
    pub bytes_each: u64,
    /// `count * bytes_each`, or the budget for a line given as one.
    pub total: u64,
    /// The configuration fields it read.
    pub inputs: &'static [&'static str],
}

/// The report: its lines, in the three groups that make the three figures.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SizingReport {
    /// The configured regions.
    pub configured: Vec<SizingLine>,
    /// The streams clients may still add, up to `max_streams`.
    pub bounded: Vec<SizingLine>,
    /// The predecessor mappings retained across a cutover or a restart.
    pub retained: Vec<SizingLine>,
    /// Bytes of the configured regions.
    pub configured_bytes: u64,
    /// Configured plus the streams clients may add.
    pub bounded_bytes: u64,
    /// Bounded plus the retained predecessor mappings: the peak.
    pub peak_bytes: u64,
}

/// Why no report could be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SizingError {
    /// A configuration value that the driver would refuse, named.
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),
    /// A sum does not fit 64 bits.
    #[error("the sizes overflow")]
    Overflow,
}

/// The bytes of a region of `structure` bytes, header included.
fn region(structure: Option<usize>, what: &'static str) -> Result<u64, SizingError> {
    structure
        .and_then(region_length)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(SizingError::Invalid(what))
}

fn line(
    region: impl Into<String>,
    count: u64,
    bytes_each: u64,
    inputs: &'static [&'static str],
) -> Result<SizingLine, SizingError> {
    Ok(SizingLine {
        region: region.into(),
        count,
        bytes_each,
        total: count.checked_mul(bytes_each).ok_or(SizingError::Overflow)?,
        inputs,
    })
}

fn sum(lines: &[SizingLine]) -> Result<u64, SizingError> {
    lines
        .iter()
        .try_fold(0u64, |total, line| total.checked_add(line.total))
        .ok_or(SizingError::Overflow)
}

/// The bytes of one generation of `stream`'s log buffer, and of its
/// conflation table when it has one.
fn stream_bytes(stream: &StreamConfig) -> Result<(u64, u64), SizingError> {
    let buffer = region(
        LogBuffer::<SharedTerms>::structure_length(&stream.buffer),
        "a stream's log buffer configuration",
    )?;
    let table = match &stream.conflation {
        Some(conflation) => region(
            conflation.structure_length(),
            "a stream's conflation configuration",
        )?,
        None => 0,
    };
    Ok((buffer, table))
}

/// The sizing report of a driver of `config` in IPC mode serving `streams`
/// (R-CORE-34): from the configuration alone, with no driver running.
///
/// # Errors
///
/// [`SizingError::Invalid`] for a value the driver would refuse, naming it;
/// [`SizingError::Overflow`] when a sum does not fit 64 bits.
pub fn report(
    config: &DriverConfig,
    streams: &[StreamConfig],
) -> Result<SizingReport, SizingError> {
    let count = |value: usize| u64::try_from(value).map_err(|_| SizingError::Overflow);
    let mut configured = vec![
        line(
            "broadcast buffer",
            1,
            region(
                karyos_sys::broadcast::structure_length(config.broadcast_capacity),
                "broadcast_capacity",
            )?,
            &["broadcast_capacity"],
        )?,
        line(
            "driver counters",
            1,
            region(
                karyos_sys::counters::structure_length(config.counters_capacity),
                "counters_capacity",
            )?,
            &["counters_capacity"],
        )?,
        line(
            "client counters",
            1,
            region(
                karyos_sys::counters::structure_length(config.client_counters_capacity),
                "client_counters_capacity",
            )?,
            &["client_counters_capacity"],
        )?,
        line(
            "error log",
            1,
            region(
                karyos_sys::diag::error_log_structure_length(config.error_log_records),
                "error_log_records",
            )?,
            &["error_log_records"],
        )?,
        line(
            "loss report",
            1,
            region(
                karyos_sys::diag::loss_report_structure_length(config.loss_report_records),
                "loss_report_records",
            )?,
            &["loss_report_records"],
        )?,
        line(
            "trace mirror",
            1,
            region(
                karyos_sys::trace_mirror::structure_length(
                    config.max_trace_journals,
                    config.trace_recycle_log_entries,
                    config.trace_mirror_records,
                ),
                "max_trace_journals, trace_recycle_log_entries or trace_mirror_records",
            )?,
            &[
                "max_trace_journals",
                "trace_recycle_log_entries",
                "trace_mirror_records",
            ],
        )?,
        line(
            "guard audit",
            1,
            region(
                karyos_sys::diag::guard_audit_structure_length(config.guard_audit_records.max(1)),
                "guard_audit_records",
            )?,
            &["guard_audit_records"],
        )?,
        line(
            "guard region",
            1,
            crate::shared_words::region_bytes(config.max_guards)
                .ok_or(SizingError::Invalid("max_guards"))?,
            &["max_guards"],
        )?,
        line(
            "command rings",
            count(config.max_clients)?,
            region(
                karyos_sys::command_ring::structure_length(config.ring_capacity),
                "ring_capacity",
            )?,
            &["max_clients", "ring_capacity"],
        )?,
        SizingLine {
            region: "client trace journals (budget)".to_owned(),
            count: 1,
            bytes_each: config.max_trace_journal_bytes,
            total: config.max_trace_journal_bytes,
            inputs: &["max_trace_journal_bytes"],
        },
    ];
    if config.network.is_some() {
        configured.push(SizingLine {
            region: "network trace journals (budget)".to_owned(),
            count: 1,
            bytes_each: config.max_network_journal_bytes,
            total: config.max_network_journal_bytes,
            inputs: &["max_network_journal_bytes"],
        });
    }
    if streams.len() > config.max_streams {
        return Err(SizingError::Invalid("more streams than max_streams"));
    }
    let mut largest = 0u64;
    let mut retained = Vec::new();
    let generations = count(config.max_retained_generations)?;
    for (index, stream) in streams.iter().enumerate() {
        let (buffer, table) = stream_bytes(stream)?;
        let name = format!("stream {} (declared {index})", stream.buffer.stream_id);
        configured.push(line(
            format!("{name}: log buffer"),
            1,
            buffer,
            &[
                "stream term_length",
                "spare_slots",
                "max_subscribers",
                "mtu",
            ],
        )?);
        if table > 0 {
            configured.push(line(
                format!("{name}: conflation table"),
                1,
                table,
                &[
                    "stream conflation keys",
                    "value_capacity",
                    "journal_capacity",
                ],
            )?);
        }
        retained.push(line(
            format!("{name}: retained generations"),
            generations,
            buffer,
            &["max_retained_generations", "stream term_length"],
        )?);
        largest = largest.max(buffer.checked_add(table).ok_or(SizingError::Overflow)?);
    }
    let mut bounded = Vec::new();
    let more = count(config.max_streams - streams.len())?;
    if more > 0 && largest > 0 {
        bounded.push(line(
            "streams clients may add, each at the largest declared stream",
            more,
            largest,
            &["max_streams", "the declared streams"],
        )?);
        retained.push(line(
            "retained generations of the streams clients may add",
            more.checked_mul(generations).ok_or(SizingError::Overflow)?,
            largest,
            &["max_streams", "max_retained_generations"],
        )?);
    }
    let configured_bytes = sum(&configured)?;
    let bounded_bytes = configured_bytes
        .checked_add(sum(&bounded)?)
        .ok_or(SizingError::Overflow)?;
    let peak_bytes = bounded_bytes
        .checked_add(sum(&retained)?)
        .ok_or(SizingError::Overflow)?;
    Ok(SizingReport {
        configured,
        bounded,
        retained,
        configured_bytes,
        bounded_bytes,
        peak_bytes,
    })
}

impl fmt::Display for SizingReport {
    /// The report as text: each group's lines with their inputs, the three
    /// figures, what the cgroup counts and what is excluded.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (title, lines) in [
            ("configured", &self.configured),
            ("streams clients may add", &self.bounded),
            ("retained across a cutover or restart", &self.retained),
        ] {
            writeln!(f, "{title}:")?;
            if lines.is_empty() {
                writeln!(f, "  (none)")?;
            }
            for line in lines {
                writeln!(
                    f,
                    "  {:<60} {:>4} x {:>14} = {:>16}  [{}]",
                    line.region,
                    line.count,
                    line.bytes_each,
                    line.total,
                    line.inputs.join(", ")
                )?;
            }
        }
        writeln!(
            f,
            "configured steady state: {} bytes",
            self.configured_bytes
        )?;
        writeln!(f, "bounded steady state:    {} bytes", self.bounded_bytes)?;
        writeln!(f, "restart peak:            {} bytes", self.peak_bytes)?;
        writeln!(
            f,
            "cgroup: every region is a shared memfd, charged once to the cgroup of \
             the process that first touches each page; the figures are mapped bytes, \
             a ceiling."
        )?;
        writeln!(f, "excluded:")?;
        for excluded in EXCLUDED {
            writeln!(f, "  - {excluded}")?;
        }
        Ok(())
    }
}
