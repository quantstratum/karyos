// SPDX-License-Identifier: Apache-2.0

//! The driver's error log and loss report (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Error log" and "Loss
//! report"): the conductor turns refusals, faults and losses into records
//! on the control path. Data-path code never formats or writes one.

use karyos_sys::diag::{
    ErrorLog, ErrorLogReader, LossRecord, LossReport, LossReportReader, Reported,
};
use karyos_sys::host_clock::host_monotonic_ns;

use crate::counters::{DriverCounters, Event};
use crate::error::DriverError;

/// Error codes: a stable `u32` enum, never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    /// A client sent a command or message that breaks the protocol.
    ClientProtocolViolation = 1,
    /// A connection's hello was refused.
    HelloRejected = 2,
    /// A client did not drain its admission messages within the fetch
    /// deadline.
    FetchDeadlineMissed = 3,
    /// A stream configuration was refused.
    StreamConfigRejected = 4,
    /// A client counter allocation was refused for lack of resources; the
    /// key is the client and the reason (1 client limit, 2 no free cell,
    /// 3 identities exhausted).
    CounterAllocationRefused = 5,
    /// The cleaner fell behind (phase 2).
    CleanerLag = 6,
    /// Two receive paths conflicted (phase 2).
    ReceiveConflict = 7,
}

/// The agent that reported an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorSource {
    /// The driver conductor, admission included.
    Conductor = 1,
}

/// Loss kinds of the loss report: a stable `u16` enum, never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum LossKind {
    /// A subscriber was overrun (`ReportLoss`). The configured policy is a
    /// `RejoinPolicyCode`, the applied one a `RejoinOutcomeCode` (for
    /// `replay`, its secondary's outcome) and the reason a
    /// `FallbackReasonCode`, 0 unless `replay` fell back.
    Overrun = 1,
    /// A required participant was lost. Its range is `[position,
    /// position)`, empty: the participant's position at the loss, with no
    /// data claimed lost.
    RequiredParticipantLost = 2,
    /// An incarnation was aborted by the `abort` policy.
    AbortedIncarnation = 3,
}

/// The loss record flag of a report the driver could not verify: its
/// participant had already ended (bit 0).
pub(crate) const LOSS_UNVERIFIED: u8 = 1;

/// A rejoin policy as a loss record carries it: the wire codes of
/// `LossPolicyCode`.
pub(crate) const fn policy_code(policy: karyos_sys::log_buffer::LossPolicy) -> u8 {
    match policy {
        karyos_sys::log_buffer::LossPolicy::Hold => 1,
        karyos_sys::log_buffer::LossPolicy::Continue => 2,
        karyos_sys::log_buffer::LossPolicy::Abort => 3,
    }
}

/// The error log and the loss report, written only by the conductor.
#[derive(Debug)]
pub(crate) struct Diagnostics {
    errors: ErrorLog,
    losses: LossReport,
}

impl Diagnostics {
    /// Both rings on the heap.
    pub(crate) fn new(config: &crate::DriverConfig) -> Result<Self, DriverError> {
        Ok(Self {
            errors: karyos_sys::diag::error_log(
                config.error_log_records,
                config.error_dedup_window,
            )
            .map_err(|_| DriverError::InvalidConfig)?,
            losses: karyos_sys::diag::loss_report(config.loss_report_records)
                .map_err(|_| DriverError::InvalidConfig)?,
        })
    }

    /// Both rings in driver-only shared regions (IPC mode), with fresh
    /// region ids.
    #[cfg(target_os = "linux")]
    pub(crate) fn new_in<T: crate::embedded::StreamTerms>(
        admission: &mut crate::admission::Admission<T>,
        config: &crate::DriverConfig,
    ) -> Result<Self, DriverError> {
        let (instance, errors) = admission.next_region()?;
        let (_, losses) = admission.next_region()?;
        Ok(Self {
            errors: karyos_sys::diag::error_log_in(
                instance,
                errors,
                config.error_log_records,
                config.error_dedup_window,
            )?,
            losses: karyos_sys::diag::loss_report_in(instance, losses, config.loss_report_records)?,
        })
    }

    /// Records an error now, deduplicated by `(code, key)`; counts an
    /// overwritten record.
    pub(crate) fn error(
        &mut self,
        counters: &mut DriverCounters,
        code: ErrorCode,
        key: [u64; 2],
        message: &str,
    ) {
        let reported = self.errors.report(
            host_monotonic_ns(),
            code as u32,
            ErrorSource::Conductor as u16,
            key,
            message,
        );
        match reported {
            Some(Reported::New {
                overwrote: true, ..
            }) => counters.add(Event::ErrorRecordsOverwritten, 1),
            Some(_) => {}
            // Sequences exhausted: the event cannot be recorded.
            None => counters.add(Event::ErrorEventsDropped, 1),
        }
    }

    /// Appends a loss record stamped now; counts an overwritten record.
    pub(crate) fn loss(&mut self, counters: &mut DriverCounters, record: LossRecord) {
        let record = LossRecord {
            time: host_monotonic_ns(),
            ..record
        };
        if self
            .losses
            .record(&record)
            .is_some_and(|appended| appended.overwrote.is_some())
        {
            counters.add(Event::LossRecordsOverwritten, 1);
        }
    }

    /// A reader of the error log.
    pub(crate) fn error_reader(&self) -> ErrorLogReader {
        self.errors.reader()
    }

    /// A reader of the loss report.
    pub(crate) fn loss_reader(&self) -> LossReportReader {
        self.losses.reader()
    }
}
