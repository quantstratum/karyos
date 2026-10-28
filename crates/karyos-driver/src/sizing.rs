// SPDX-License-Identifier: Apache-2.0

//! A sizing report of a driver in IPC mode (Linux; R-CORE-34): the bytes of
//! every shared region the driver and its clients map, computed from the
//! configuration alone, with no driver running.
//!
//! Every figure comes from the same function that sizes the region when it
//! is created (`karyos_sys::sizing::region_length` over each kind's
//! structure length), rounded up to the page, since every region is its own
//! `memfd` and is mapped and charged in whole pages. Every line names the
//! configuration inputs it read.
//!
//! The report gives two figures:
//!
//! - **configured steady state**: the fixed regions, `max_clients` command
//!   rings, the client trace journal budget, the declared streams with
//!   their conflation tables, and the network trace journal budget, which
//!   lives on the heap and is listed apart;
//! - **restart peak**: configured plus, for every declared stream, its
//!   `max_retained_generations` predecessor mappings, which a cutover or a
//!   restart keeps mapped for readers that have not finished. It assumes
//!   no `reconfigure_stream` or `reconfigure_aggregate` since start, so
//!   that a predecessor has the current geometry; the report states that
//!   assumption.
//!
//! Streams added after start, by the host or as replay targets a client
//! asks for, are excluded: no configuration bounds their geometry, so no
//! figure could bound them.
//!
//! **What the cgroup counts.** A shared page is charged once, to the memory
//! cgroup of the process that first touches it, however many processes map
//! it. In a pod whose processes share one cgroup, each region counts once.
//! The figures are mapped pages, a ceiling: a page never touched is never
//! charged.

use core::fmt;
use std::collections::BTreeSet;

use karyos_sys::log_buffer::LogBuffer;
use karyos_sys::sizing::region_length;
use karyos_sys::term_bytes::SharedTerms;

use crate::embedded::{DriverConfig, StreamConfig};

/// What the report does not cover.
pub const EXCLUDED: [&str; 7] = [
    "streams added after start and Archive replay targets: no configuration sets their maximum geometry, so nothing bounds them",
    "the application's and karyosd's own heap, code and thread stacks, except the network trace journal budget",
    "kernel socket buffers and network receive buffers",
    "the Archive's page cache and recording files",
    "page tables and other kernel memory",
    "the network image lanes and network publications, sized by remote senders and URIs, not by this configuration",
    "the outcome rings and consumed cells of guarded handles, one pair per handle a client takes",
];

/// The assumption the restart peak rests on.
pub const PEAK_ASSUMPTION: &str = "no reconfigure_stream or reconfigure_aggregate since start: \
     a retained predecessor has its stream's current geometry; after a \
     reconfiguration, size with the largest geometry the stream has had";

/// One line of the report: a kind of region, how many, and the
/// configuration inputs it read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SizingLine {
    /// What the regions hold.
    pub region: String,
    /// How many.
    pub count: u64,
    /// Bytes of each, header included, rounded up to the page; a budget's
    /// bytes as configured.
    pub bytes_each: u64,
    /// `count * bytes_each`.
    pub total: u64,
    /// The configuration fields it read.
    pub inputs: &'static [&'static str],
}

/// The report: its lines, in groups, and its two figures.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SizingReport {
    /// The configured shared regions.
    pub configured: Vec<SizingLine>,
    /// The configured budgets that live on the heap, not in a region.
    pub heap: Vec<SizingLine>,
    /// The predecessor mappings retained across a cutover or a restart.
    pub retained: Vec<SizingLine>,
    /// Bytes of the configured regions and heap budgets.
    pub configured_bytes: u64,
    /// Configured plus the retained predecessor mappings, under
    /// [`PEAK_ASSUMPTION`].
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

/// Sizes regions in whole pages of `page` bytes.
struct Pages(u64);

impl Pages {
    /// The mapped bytes of a region of `structure` bytes: header included,
    /// rounded up to the page.
    fn region(&self, structure: Option<usize>, what: &'static str) -> Result<u64, SizingError> {
        let bytes = structure
            .and_then(region_length)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(SizingError::Invalid(what))?;
        self.round(bytes)
    }

    fn round(&self, bytes: u64) -> Result<u64, SizingError> {
        bytes
            .checked_next_multiple_of(self.0)
            .ok_or(SizingError::Overflow)
    }
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

/// The mapped bytes of one generation of `stream`'s log buffer, and of its
/// conflation table when it has one.
fn stream_bytes(pages: &Pages, stream: &StreamConfig) -> Result<(u64, u64), SizingError> {
    let buffer = pages.region(
        LogBuffer::<SharedTerms>::structure_length(&stream.buffer),
        "a stream's log buffer configuration",
    )?;
    let table = match &stream.conflation {
        Some(conflation) => pages.region(
            conflation.structure_length(),
            "a stream's conflation configuration",
        )?,
        None => 0,
    };
    Ok((buffer, table))
}

/// The sizing report of a driver of `config` in IPC mode serving `streams`
/// (R-CORE-34), with regions mapped in pages of `page_size` bytes (`karyos_sys::ipc::page_size`): from the
/// configuration alone, with no driver running.
///
/// # Errors
///
/// [`SizingError::Invalid`] for a value the driver would refuse, naming it:
/// a configuration `DriverConfig::validate` refuses, more streams than
/// `max_streams`, two streams with one stream and session id, or a stream
/// or table a buffer refuses; [`SizingError::Overflow`] when a sum does not
/// fit 64 bits.
pub fn report(
    config: &DriverConfig,
    streams: &[StreamConfig],
    page_size: usize,
) -> Result<SizingReport, SizingError> {
    config
        .validate()
        .map_err(|_| SizingError::Invalid("the driver configuration"))?;
    if streams.len() > config.max_streams {
        return Err(SizingError::Invalid("more streams than max_streams"));
    }
    let mut keys = BTreeSet::new();
    if !streams
        .iter()
        .all(|stream| keys.insert((stream.buffer.stream_id, stream.buffer.session_id)))
    {
        return Err(SizingError::Invalid(
            "two streams with one stream and session id",
        ));
    }
    let pages = Pages(
        u64::try_from(page_size)
            .ok()
            .filter(|page| page.is_power_of_two())
            .ok_or(SizingError::Invalid("the page size"))?,
    );
    let count = |value: usize| u64::try_from(value).map_err(|_| SizingError::Overflow);
    let mut configured = vec![
        line(
            "broadcast buffer",
            1,
            pages.region(
                karyos_sys::broadcast::structure_length(config.broadcast_capacity),
                "broadcast_capacity",
            )?,
            &["broadcast_capacity"],
        )?,
        line(
            "driver counters",
            1,
            pages.region(
                karyos_sys::counters::structure_length(config.counters_capacity),
                "counters_capacity",
            )?,
            &["counters_capacity"],
        )?,
        line(
            "client counters",
            1,
            pages.region(
                karyos_sys::counters::structure_length(config.client_counters_capacity),
                "client_counters_capacity",
            )?,
            &["client_counters_capacity"],
        )?,
        line(
            "error log",
            1,
            pages.region(
                karyos_sys::diag::error_log_structure_length(config.error_log_records),
                "error_log_records",
            )?,
            &["error_log_records"],
        )?,
        line(
            "loss report",
            1,
            pages.region(
                karyos_sys::diag::loss_report_structure_length(config.loss_report_records),
                "loss_report_records",
            )?,
            &["loss_report_records"],
        )?,
        line(
            "trace mirror",
            1,
            pages.region(
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
            pages.region(
                karyos_sys::diag::guard_audit_structure_length(config.guard_audit_records.max(1)),
                "guard_audit_records",
            )?,
            &["guard_audit_records"],
        )?,
        line(
            "guard region",
            1,
            pages.round(
                crate::shared_words::region_bytes(config.max_guards)
                    .ok_or(SizingError::Invalid("max_guards"))?,
            )?,
            &["max_guards"],
        )?,
        line(
            "command rings",
            count(config.max_clients)?,
            pages.region(
                karyos_sys::command_ring::structure_length(config.ring_capacity),
                "ring_capacity",
            )?,
            &["max_clients", "ring_capacity"],
        )?,
        // A budget over all journals, each its own region: at most one
        // partial page per journal beyond it.
        line(
            "client trace journals (budget, plus a page per journal)",
            1,
            config
                .max_trace_journal_bytes
                .checked_add(
                    count(config.max_trace_journals)?
                        .checked_mul(pages.0)
                        .ok_or(SizingError::Overflow)?,
                )
                .ok_or(SizingError::Overflow)?,
            &["max_trace_journal_bytes", "max_trace_journals"],
        )?,
    ];
    let mut retained = Vec::new();
    let generations = count(config.max_retained_generations)?;
    for (index, stream) in streams.iter().enumerate() {
        let (buffer, table) = stream_bytes(&pages, stream)?;
        let name = format!(
            "stream {}:{} (declared {index})",
            stream.buffer.stream_id, stream.buffer.session_id
        );
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
        // A cutover replaces the log buffer only; the table stays.
        retained.push(line(
            format!("{name}: retained generations"),
            generations,
            buffer,
            &["max_retained_generations", "stream term_length"],
        )?);
    }
    let mut heap = Vec::new();
    if config.network.is_some() {
        heap.push(line(
            "network trace journals (budget)",
            1,
            config.max_network_journal_bytes,
            &["max_network_journal_bytes"],
        )?);
    }
    let configured_bytes = sum(&configured)?
        .checked_add(sum(&heap)?)
        .ok_or(SizingError::Overflow)?;
    let peak_bytes = configured_bytes
        .checked_add(sum(&retained)?)
        .ok_or(SizingError::Overflow)?;
    Ok(SizingReport {
        configured,
        heap,
        retained,
        configured_bytes,
        peak_bytes,
    })
}

impl fmt::Display for SizingReport {
    /// The report as text: each group's lines with their inputs, the two
    /// figures, the peak's assumption, what the cgroup counts and what is
    /// excluded.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (title, lines) in [
            ("configured shared regions", &self.configured),
            ("configured heap budgets", &self.heap),
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
        writeln!(f, "restart peak:            {} bytes", self.peak_bytes)?;
        writeln!(f, "the restart peak assumes {PEAK_ASSUMPTION}.")?;
        writeln!(
            f,
            "cgroup: every region is a shared memfd, mapped in whole pages and \
             charged once to the cgroup of the process that first touches each \
             page; the figures are mapped pages, a ceiling."
        )?;
        writeln!(f, "excluded:")?;
        for excluded in EXCLUDED {
            writeln!(f, "  - {excluded}")?;
        }
        Ok(())
    }
}
