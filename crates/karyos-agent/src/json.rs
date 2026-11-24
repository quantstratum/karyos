// SPDX-License-Identifier: Apache-2.0

//! API v1 as JSON, written by hand (quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md, M7; owner item 51:
//! no `serde` until one is admitted, and the schema stays the same then).
//!
//! - **Fields.** Each type is an object with its fields under their Rust
//!   names, in declaration order. An `Option` that is `None` is `null`.
//! - **Numbers.** Integers are written exactly. A `u64` may pass 2^53, so a
//!   reader that parses numbers as doubles (JavaScript) must read them as
//!   big integers. The 128-bit driver instance is a string of 32 lowercase
//!   hex digits.
//! - **Strings.** UTF-8, with `"`, `\` and the control characters escaped;
//!   a path that is not UTF-8 is written lossily.
//! - **Enums.** [`DriverState`] is an object with a `state` field
//!   (`"attached"`, `"closed"`, `"unavailable"`) and its variant's fields;
//!   an [`AlertKind`] is a string (`"lag"`, `"loss"`, `"guard_ack"`, `"journal_gap"`).

use std::fmt::Write;

use crate::api::{
    AgentIdentity, AgentView, Alert, AlertKind, AttachEndReason, Attachment, Capability,
    CapabilityState, Catalog, CatalogRecording, Counter, DriverState, DriverView, ErrorEntry, Feed,
    GuardEntry, JournalView, Lane, LaneLatency, LossEntry, Sample, Subscriber, TraceCounts,
};
use crate::api::{BucketLane, BucketRead, BucketRefusal, TraceBucket};
use crate::api::{ExportJournal, ExportPage, ExportRefusal};
use crate::api::{RecordingRetention, RetentionView};

/// A JSON value being written into a string.
struct Out<'a>(&'a mut String);

impl Out<'_> {
    fn raw(&mut self, text: &str) {
        self.0.push_str(text);
    }

    fn string(&mut self, text: &str) {
        self.0.push('"');
        for c in text.chars() {
            match c {
                '"' => self.0.push_str("\\\""),
                '\\' => self.0.push_str("\\\\"),
                '\n' => self.0.push_str("\\n"),
                '\r' => self.0.push_str("\\r"),
                '\t' => self.0.push_str("\\t"),
                c if u32::from(c) < 0x20 => {
                    let _ = write!(self.0, "\\u{:04x}", u32::from(c));
                }
                c => self.0.push(c),
            }
        }
        self.0.push('"');
    }

    fn number(&mut self, value: impl core::fmt::Display) {
        let _ = write!(self.0, "{value}");
    }

    fn bool(&mut self, value: bool) {
        self.raw(if value { "true" } else { "false" });
    }

    fn option<T>(&mut self, value: Option<T>, mut write: impl FnMut(&mut Self, T)) {
        match value {
            Some(value) => write(self, value),
            None => self.raw("null"),
        }
    }

    fn array<T>(&mut self, items: &[T], mut write: impl FnMut(&mut Self, &T)) {
        self.raw("[");
        for (index, item) in items.iter().enumerate() {
            if index > 0 {
                self.raw(",");
            }
            write(self, item);
        }
        self.raw("]");
    }

    /// An object: `fields` writes each `key` and value through [`Fields`].
    fn object(&mut self, fields: impl FnOnce(&mut Fields<'_, '_>)) {
        self.raw("{");
        let mut object = Fields {
            out: self,
            first: true,
        };
        fields(&mut object);
        self.raw("}");
    }
}

/// The fields of an object being written.
struct Fields<'a, 'b> {
    out: &'a mut Out<'b>,
    first: bool,
}

impl<'b> Fields<'_, 'b> {
    fn key(&mut self, key: &str) -> &mut Out<'b> {
        if !self.first {
            self.out.raw(",");
        }
        self.first = false;
        self.out.string(key);
        self.out.raw(":");
        self.out
    }

    fn number(&mut self, key: &str, value: impl core::fmt::Display) {
        self.key(key).number(value);
    }

    fn string(&mut self, key: &str, value: &str) {
        self.key(key).string(value);
    }
}

/// `view` as one JSON object.
#[must_use]
pub fn view(view: &AgentView) -> String {
    let mut text = String::new();
    Out(&mut text).object(|fields| {
        fields.number("version", view.version);
        fields
            .key("drivers")
            .array(&view.drivers, |out, driver| driver_view(out, driver));
        fields
            .key("journal")
            .option(view.journal.as_ref(), |out, journal| {
                journal_view(out, journal)
            });
        agent_identity(fields.key("agent"), &view.agent);
        fields.key("rates").array(&view.rates, |out, rate| {
            out.object(|fields| {
                fields.string("dir", &rate.dir.to_string_lossy());
                fields.number("stream_id", rate.stream_id);
                fields.number("session_id", rate.session_id);
                fields.number("version", rate.version);
                fields.number("operation", rate.operation);
            });
        });
    });
    text
}

/// The agent's identity (R-CORE-24).
fn agent_identity(out: &mut Out<'_>, agent: &AgentIdentity) {
    out.object(|fields| {
        fields
            .key("id")
            .option(agent.id.as_deref(), |out, id| out.string(id));
        fields.number("pid", agent.pid);
        fields.number("started_ns", agent.started_ns);
    });
}

/// A driver's attachment (R-CORE-24).
fn attachment(out: &mut Out<'_>, attachment: &Attachment) {
    out.object(|fields| {
        fields
            .key("since_ns")
            .option(attachment.since_ns, |out, since| out.number(since));
        fields.number("attaches", attachment.attaches);
        fields
            .key("previous")
            .option(attachment.previous, |out, end| {
                out.object(|fields| {
                    fields.string("instance", &format!("{:032x}", end.instance));
                    fields.number("ended_ns", end.ended_ns);
                    fields.string(
                        "reason",
                        match end.reason {
                            AttachEndReason::DriverGone => "driver_gone",
                            AttachEndReason::Detached => "detached",
                        },
                    );
                });
            });
    });
}

/// The answer to `capabilities` (R-CORE-24): each capability and whether
/// the caller is served it.
#[must_use]
pub fn capabilities(capabilities: &[Capability]) -> String {
    let mut text = String::new();
    Out(&mut text).object(|fields| {
        fields
            .key("capabilities")
            .array(capabilities, |out, capability| {
                out.object(|fields| {
                    fields.string("name", capability.name);
                    let (state, reason) = match capability.state {
                        CapabilityState::Served => ("served", None),
                        CapabilityState::Unavailable { reason } => ("unavailable", Some(reason)),
                        CapabilityState::Forbidden { reason } => ("forbidden", Some(reason)),
                    };
                    fields.string("state", state);
                    fields
                        .key("reason")
                        .option(reason, |out, reason| out.string(reason));
                });
            });
    });
    text
}

/// The typed error of a known request with arguments it does not take
/// (`{"error":"bad arguments","request":NAME}`; the rule of karyos#733).
#[must_use]
pub fn bad_arguments(request: &str) -> String {
    let mut text = String::new();
    Out(&mut text).object(|fields| {
        fields.string("error", "bad arguments");
        fields.string("request", request);
    });
    text
}

/// The operations journal (M10b).
fn journal_view(out: &mut Out<'_>, journal: &JournalView) {
    out.object(|fields| {
        fields
            .key("recording")
            .option(journal.recording, |out, id| out.number(id));
        fields.key("unsealed").bool(journal.unsealed);
        fields.key("unavailable").bool(journal.unavailable);
        fields
            .key("error")
            .option(journal.error.as_deref(), |out, error| out.string(error));
        fields.number("failed_appends", journal.failed_appends);
        fields.key("gap").option(journal.gap, |out, gap| {
            out.object(|fields| {
                fields.number("position", gap.position);
                fields.number("from", gap.from);
                fields.number("to", gap.to);
                fields.string("reason", gap.reason);
            });
        });
        fields
            .key("alerts")
            .array(&journal.alerts, |out, alert| alert_json(out, alert));
    });
}

/// A guard preview's answer (R-CORE-18, karyos#738): what the operation
/// would do, each field it cannot give written `"unavailable"`, never a
/// zero or a false (RR-CON-0008).
#[cfg(target_os = "linux")]
#[must_use]
pub fn preview_answer(answer: &crate::preview::PreviewAnswer) -> String {
    use crate::preview::{PREVIEW_TTL, PreviewAnswer};
    const UNAVAILABLE: &str = "unavailable";
    let mut text = String::new();
    Out(&mut text).object(|fields| match answer {
        PreviewAnswer::Previewed {
            kind,
            guard,
            instance,
            state,
            epoch_after,
            token,
        } => {
            fields.key("preview").object(|fields| {
                fields.string("operation", kind.name());
                fields.number("guard", *guard);
                fields.string("instance", &format!("{instance:032x}"));
                match state {
                    Some(state) => fields.key("state").object(|fields| {
                        fields.number("epoch", state.epoch);
                        fields.key("open").bool(state.open);
                    }),
                    None => fields.string("state", UNAVAILABLE),
                }
                match epoch_after {
                    Some(epoch) => fields.number("epoch_after", *epoch),
                    None => fields.string("epoch_after", UNAVAILABLE),
                }
            });
            match token {
                Some(token) => {
                    fields.string("token", &token.hex());
                    fields.number(
                        "expires_in_ms",
                        u64::try_from(PREVIEW_TTL.as_millis()).unwrap_or(u64::MAX),
                    );
                }
                None => fields.string("token", UNAVAILABLE),
            }
        }
        PreviewAnswer::UnknownDriver => fields.string("error", "unknown driver"),
        PreviewAnswer::Unattached => fields.string("error", "driver unavailable"),
    });
    text
}

/// A guard operation's answer (M10b): the guard's state after it, or why
/// it came to nothing; `operation` is the id it was journalled and audited
/// under, when it was sent.
#[cfg(target_os = "linux")]
#[must_use]
pub fn guard_answer(answer: &crate::operations::GuardAnswer) -> String {
    use crate::operations::GuardAnswer;
    let mut text = String::new();
    Out(&mut text).object(|fields| match *answer {
        GuardAnswer::State {
            operation,
            guard,
            state,
        } => {
            fields.number("operation", operation);
            fields.number("guard", guard);
            fields.key("state").object(|fields| {
                fields.number("epoch", state.epoch);
                fields.key("open").bool(state.open);
            });
        }
        GuardAnswer::Refused {
            operation,
            code,
            detail,
        } => {
            fields.string("error", "refused");
            fields.number("operation", operation);
            fields.number("code", code);
            fields.number("detail", detail);
        }
        GuardAnswer::NoAnswer { operation } => {
            fields.string("error", "no answer");
            fields.number("operation", operation);
        }
        GuardAnswer::JournalUnavailable => fields.string("error", "journal unavailable"),
        GuardAnswer::UnknownDriver => fields.string("error", "unknown driver"),
        GuardAnswer::Unattached => fields.string("error", "driver unavailable"),
        GuardAnswer::InstanceChanged => fields.string("error", "target changed"),
    });
    text
}

/// A rate change's answer (R-CORE-21, karyos#740): the stream's policy
/// version after it, or why it was not made, as [`guard_answer`] writes
/// its errors.
#[cfg(target_os = "linux")]
#[must_use]
pub fn rate_answer(answer: &crate::operations::RateAnswer) -> String {
    use crate::operations::RateAnswer;
    let mut text = String::new();
    Out(&mut text).object(|fields| match *answer {
        RateAnswer::State {
            operation,
            stream,
            version,
        } => {
            fields.number("operation", operation);
            fields.number("stream_id", stream.stream_id);
            fields.number("session_id", stream.session_id);
            fields.number("version", version);
        }
        RateAnswer::Refused {
            operation,
            code,
            detail,
        } => {
            fields.string("error", "refused");
            fields.number("operation", operation);
            fields.number("code", code);
            fields.number("detail", detail);
        }
        RateAnswer::NoAnswer { operation } => {
            fields.string("error", "no answer");
            fields.number("operation", operation);
        }
        RateAnswer::JournalUnavailable => fields.string("error", "journal unavailable"),
        RateAnswer::UnknownDriver => fields.string("error", "unknown driver"),
        RateAnswer::InvalidPolicy => fields.string("error", "invalid policy"),
        RateAnswer::Unattached => fields.string("error", "driver unavailable"),
    });
    text
}

/// A retention operation's answer (M12): what the Archive did or refused,
/// with its code and reason, or each range's integrity outcome as the
/// Archive named it; the agent adds no verdict of its own.
#[must_use]
pub fn retention_answer(answer: &crate::retention::RetentionAnswer) -> String {
    use crate::retention::RetentionAnswer;
    let mut text = String::new();
    Out(&mut text).object(|fields| match answer {
        RetentionAnswer::Done {
            operation,
            evidenced,
        } => {
            fields.number("operation", operation);
            fields.key("evidenced").bool(*evidenced);
        }
        RetentionAnswer::Refused {
            operation,
            code,
            reason,
        } => {
            fields.string("error", "refused");
            fields.number("operation", operation);
            fields.number("code", code);
            fields.string("reason", reason);
        }
        RetentionAnswer::Verified { operation, ranges } => {
            fields.number("operation", operation);
            fields.key("ranges").array(ranges, |out, range| {
                out.object(|fields| {
                    fields.number("start", range.start);
                    fields.number("end", range.end);
                    fields.string("outcome", &range.outcome);
                    fields
                        .key("reasons")
                        .array(&range.reasons, |out, reason| out.string(reason));
                });
            });
        }
        RetentionAnswer::NoAnswer { operation } => {
            fields.string("error", "no answer");
            fields.number("operation", operation);
        }
        RetentionAnswer::JournalUnavailable => fields.string("error", "journal unavailable"),
        RetentionAnswer::NoArchive => fields.string("error", "no archive"),
        RetentionAnswer::Busy => fields.string("error", "busy"),
    });
    text
}

/// A product Cluster's admin command's answer (R-CORE-41, karyos#772):
/// `{"operation":N,"outcome":"sequenced","index":N,"term":N,"reply":HEX,
/// "evidence":{"algorithm":S,"digest":HEX}|null}`; a product's refusal
/// `{"error":"refused","operation":N,"outcome":"refused","code":N,
/// "reason":S}`; an unknown outcome `{"error":"no answer","operation":N,
/// "outcome":"unknown"}`; the agent's refusals as `{"error":TEXT}`.
#[must_use]
pub fn cluster_answer(answer: &crate::cluster_admin::ClusterAnswer) -> String {
    use crate::cluster_admin::{ClusterAnswer, hex};
    let mut text = String::new();
    Out(&mut text).object(|fields| match answer {
        ClusterAnswer::Sequenced {
            operation,
            index,
            term,
            reply,
            evidence,
        } => {
            fields.number("operation", operation);
            fields.string("outcome", "sequenced");
            fields.number("index", index);
            fields.number("term", term);
            fields.string("reply", &hex(reply));
            fields
                .key("evidence")
                .option(evidence.as_ref(), |out, evidence| {
                    out.object(|fields| {
                        fields.string("algorithm", &evidence.algorithm);
                        fields.string("digest", &hex(&evidence.digest));
                    });
                });
        }
        ClusterAnswer::Refused {
            operation,
            code,
            reason,
        } => {
            fields.string("error", "refused");
            fields.number("operation", operation);
            fields.string("outcome", "refused");
            fields.number("code", code);
            fields.string("reason", reason);
        }
        ClusterAnswer::NoAnswer { operation } => {
            fields.string("error", "no answer");
            fields.number("operation", operation);
            fields.string("outcome", "unknown");
        }
        ClusterAnswer::Rejected(code) => fields.string("error", code.text()),
        ClusterAnswer::JournalUnavailable => fields.string("error", "journal unavailable"),
        ClusterAnswer::Busy => fields.string("error", "busy"),
    });
    text
}

/// The answer to an acknowledged unknown interval (M10b).
#[must_use]
pub fn acknowledged(position: u64) -> String {
    let mut text = String::new();
    Out(&mut text).object(|fields| fields.number("acknowledged", position));
    text
}

/// `limits`' answer: each dimension's effective value and whether it is
/// negotiable, or `{"value":null}` for one with no bound (R-CORE-38).
#[must_use]
pub fn limits(limits: &[crate::api::Limit], effective: &[Option<u64>]) -> String {
    let mut text = String::new();
    Out(&mut text).object(|fields| {
        fields.key("limits").object(|dimensions| {
            for (limit, value) in limits.iter().zip(effective) {
                dimensions.key(limit.name).object(|answer| match value {
                    Some(value) => {
                        answer.number("value", value);
                        answer.key("negotiable").bool(limit.negotiable);
                    }
                    None => answer.key("value").raw("null"),
                });
            }
        });
    });
    text
}

/// The refusal of a proposal above `limit`'s bound, carrying the bound.
#[must_use]
pub fn above_bound(limit: &crate::api::Limit) -> String {
    let mut text = String::new();
    Out(&mut text).object(|fields| {
        fields.string("error", "above bound");
        fields.string("dimension", limit.name);
        fields
            .key("bound")
            .option(limit.bound, |out, bound| out.number(bound));
    });
    text
}

/// The refusal of a proposal for a dimension this agent does not know.
#[must_use]
pub fn unknown_dimension(name: &str) -> String {
    let mut text = String::new();
    Out(&mut text).object(|fields| {
        fields.string("error", "unknown dimension");
        fields.string("dimension", name);
    });
    text
}

/// An error answer: `{"error": message}` with `detail`'s fields.
#[must_use]
pub fn error(message: &str, supported: Option<&[u32]>) -> String {
    let mut text = String::new();
    Out(&mut text).object(|fields| {
        fields.string("error", message);
        if let Some(supported) = supported {
            fields
                .key("supported")
                .array(supported, |out, version| out.number(version));
        }
    });
    text
}

fn driver_view(out: &mut Out<'_>, driver: &DriverView) {
    out.object(|fields| {
        fields.string("dir", &driver.dir.to_string_lossy());
        let state = fields.key("state");
        state.object(|fields| match &driver.state {
            DriverState::Attached => fields.string("state", "attached"),
            DriverState::Closed => fields.string("state", "closed"),
            DriverState::Unavailable { reason } => {
                fields.string("state", "unavailable");
                fields.string("reason", reason);
            }
        });
        fields
            .key("instance")
            .option(driver.instance, |out, instance| {
                out.string(&format!("{instance:032x}"));
            });
        fields
            .key("sample")
            .option(driver.sample.as_ref(), |out, sample| {
                sample_json(out, sample)
            });
        fields
            .key("client_counters")
            .array(&driver.client_counters, |out, counter| {
                counter_json(out, counter)
            });
        feed(fields.key("errors"), &driver.errors, error_entry);
        feed(fields.key("losses"), &driver.losses, loss_entry);
        feed(fields.key("guards"), &driver.guards, guard_entry);
        fields
            .key("latencies")
            .array(&driver.latencies, |out, latency| lane_latency(out, latency));
        trace_counts(fields.key("trace"), &driver.trace);
        fields
            .key("alerts")
            .array(&driver.alerts, |out, alert| alert_json(out, alert));
        fields
            .key("catalog")
            .option(driver.catalog.as_ref(), catalog_json);
        attachment(fields.key("attachment"), &driver.attachment);
    });
}

/// A driver's Archive catalog (M11).
fn catalog_json(out: &mut Out<'_>, catalog: &Catalog) {
    out.object(|fields| {
        fields
            .key("recordings")
            .array(&catalog.recordings, |out, recording| {
                catalog_recording(out, recording)
            });
        fields.number("left_out", catalog.left_out);
        fields
            .key("listed_at")
            .option(catalog.listed_at, |out, at| out.number(at));
        fields.number("listings", catalog.listings);
        fields.number("failures", catalog.failures);
        fields
            .key("last_error")
            .option(catalog.last_error.as_deref(), |out, error| {
                out.string(error)
            });
        fields
            .key("retention")
            .option(catalog.retention.as_ref(), retention_json);
    });
}

/// An Archive's retention state (ADR-0101; karyos#967).
fn retention_json(out: &mut Out<'_>, retention: &RetentionView) {
    out.object(|fields| {
        fields
            .key("recordings")
            .array(&retention.recordings, |out, recording| {
                recording_retention(out, recording)
            });
        fields.number("min_free_bytes", retention.min_free_bytes);
        fields
            .key("free_bytes")
            .option(retention.free_bytes, |out, free| out.number(free));
        fields
            .key("read_at")
            .option(retention.read_at, |out, at| out.number(at));
        fields
            .key("last_error")
            .option(retention.last_error.as_deref(), |out, error| {
                out.string(error)
            });
    });
}

fn recording_retention(out: &mut Out<'_>, recording: &RecordingRetention) {
    out.object(|fields| {
        fields.number("recording_id", recording.recording_id);
        fields.string("hold", recording.hold);
        fields
            .key("hold_since_ns")
            .option(recording.hold_since_ns, |out, at| out.number(at));
        fields
            .key("close_time_ns")
            .option(recording.close_time_ns, |out, at| out.number(at));
        fields
            .key("earliest_expiry_ns")
            .option(recording.earliest_expiry_ns, |out, at| out.number(at));
        fields
            .key("policy")
            .option(recording.policy, |out, (policy, version)| {
                out.object(|fields| {
                    fields.number("id", policy);
                    fields.number("version", version);
                });
            });
    });
}

fn catalog_recording(out: &mut Out<'_>, recording: &CatalogRecording) {
    out.object(|fields| {
        fields.number("recording_id", recording.recording_id);
        fields.number("stream_id", recording.stream_id);
        fields.number("session_id", recording.session_id);
        fields.string("channel", &recording.channel);
        fields.number("start", recording.start);
        fields.number("start_time_ns", recording.start_time_ns);
        fields.key("recording").bool(recording.recording);
        fields.number("position", recording.position);
        fields
            .key("stopped_ns")
            .option(recording.stopped_ns, |out, at| out.number(at));
        fields
            .key("stop_reason")
            .option(recording.stop_reason.as_deref(), |out, reason| {
                out.string(reason)
            });
        fields.key("incomplete").bool(recording.incomplete);
    });
}

/// One lane's trace window: observed latencies, never verdicts (M6c).
fn lane_latency(out: &mut Out<'_>, latency: &LaneLatency) {
    out.object(|fields| {
        fields.number("stream", latency.stream);
        fields.number("incarnation", latency.incarnation);
        fields.number("lane", latency.lane);
        fields.number("available", latency.available);
        fields.number("unavailable", latency.unavailable);
        fields.key("incomplete").bool(latency.incomplete);
        for (key, bounds) in [
            ("p50", latency.p50),
            ("p90", latency.p90),
            ("p99", latency.p99),
            ("p999", latency.p999),
            ("max", latency.max),
        ] {
            fields.key(key).option(bounds, |out, bounds| {
                out.object(|fields| {
                    fields
                        .key("low")
                        .option(bounds.low, |out, low| out.number(low));
                    fields
                        .key("high")
                        .option(bounds.high, |out, high| out.number(high));
                });
            });
        }
    });
}

fn trace_counts(out: &mut Out<'_>, counts: &TraceCounts) {
    out.object(|fields| {
        for (key, value) in [
            ("records", counts.records),
            ("malformed", counts.malformed),
            ("unknown_journal", counts.unknown_journal),
            ("network_ignored", counts.network_ignored),
            ("points_ignored", counts.points_ignored),
            ("duplicates", counts.duplicates),
            ("journals_dropped", counts.journals_dropped),
            ("pending_dropped", counts.pending_dropped),
            ("polls_dropped", counts.polls_dropped),
            ("lanes_dropped", counts.lanes_dropped),
            ("aged_out", counts.aged_out),
            ("mirror_overwritten", counts.mirror_overwritten),
            ("pending", counts.pending),
            ("buckets_evicted", counts.buckets_evicted),
            ("buckets_over_budget", counts.buckets_over_budget),
        ] {
            fields.number(key, value);
        }
    });
}

fn alert_json(out: &mut Out<'_>, alert: &Alert) {
    out.object(|fields| {
        fields.string(
            "kind",
            match alert.kind {
                AlertKind::Lag => "lag",
                AlertKind::Loss => "loss",
                AlertKind::GuardAck => "guard_ack",
                AlertKind::JournalGap => "journal_gap",
            },
        );
        fields.number("stream", alert.stream);
        fields.number("lane", alert.lane);
        fields.number("participant", alert.participant);
        fields.number("value", alert.value);
        fields.number("since", alert.since);
    });
}

fn sample_json(out: &mut Out<'_>, sample: &Sample) {
    out.object(|fields| {
        fields.key("consistent").bool(sample.consistent);
        fields.key("sampled").bool(sample.sampled);
        fields
            .key("age_ns")
            .option(sample.age_ns, |out, age| out.number(age));
        fields
            .key("counters")
            .array(&sample.counters, |out, counter| counter_json(out, counter));
        fields
            .key("lanes")
            .array(&sample.lanes, |out, lane| lane_json(out, lane));
    });
}

fn counter_json(out: &mut Out<'_>, counter: &Counter) {
    out.object(|fields| {
        fields.string("label", &counter.label);
        fields.number("type_id", counter.type_id);
        fields.number("stream", counter.stream);
        fields.number("lane", counter.lane);
        fields.number("kind", counter.kind);
        fields.number("participant", counter.participant);
        fields.number("cell_registration", counter.cell_registration);
        fields.number("value", counter.value);
        fields.number("read_ns", counter.read_ns);
        fields
            .key("changed_ns")
            .option(counter.changed_ns, |out, at| out.number(at));
    });
}

fn lane_json(out: &mut Out<'_>, lane: &Lane) {
    out.object(|fields| {
        fields.number("stream", lane.stream);
        fields.number("lane", lane.lane);
        fields
            .key("limit")
            .option(lane.limit, |out, value| out.number(value));
        fields
            .key("head")
            .option(lane.head, |out, value| out.number(value));
        fields
            .key("floor")
            .option(lane.floor, |out, value| out.number(value));
        fields
            .key("headroom")
            .option(lane.headroom, |out, value| out.number(value));
        fields
            .key("subscribers")
            .array(&lane.subscribers, |out, subscriber| {
                subscriber_json(out, subscriber)
            });
        fields
            .key("sampled_ns")
            .option(lane.sampled_ns, |out, at| out.number(at));
    });
}

fn subscriber_json(out: &mut Out<'_>, subscriber: &Subscriber) {
    out.object(|fields| {
        fields.number("registration", subscriber.registration);
        fields.number("cell_registration", subscriber.cell_registration);
        fields.string("label", &subscriber.label);
        fields.number("position", subscriber.position);
        fields
            .key("lag")
            .option(subscriber.lag, |out, value| out.number(value));
        fields
            .key("changed_ns")
            .option(subscriber.changed_ns, |out, at| out.number(at));
    });
}

fn feed<T>(out: &mut Out<'_>, feed: &Feed<T>, entry: fn(&mut Out<'_>, &T)) {
    out.object(|fields| {
        fields.key("records").array(&feed.records, entry);
        fields.number("delivered", feed.delivered);
        fields.number("overwritten", feed.overwritten);
    });
}

fn error_entry(out: &mut Out<'_>, entry: &ErrorEntry) {
    out.object(|fields| {
        fields.number("seq", entry.seq);
        fields.number("first", entry.first);
        fields.number("last", entry.last);
        fields.number("occurrences", entry.occurrences);
        fields.number("code", entry.code);
        fields.number("source", entry.source);
        fields
            .key("key")
            .array(&entry.key, |out, value| out.number(value));
        fields.string("message", &entry.message);
    });
}

fn loss_entry(out: &mut Out<'_>, entry: &LossEntry) {
    out.object(|fields| {
        fields.number("seq", entry.seq);
        fields.number("time", entry.time);
        fields.number("kind", entry.kind);
        fields.number("reason", entry.reason);
        fields.number("lane", entry.lane);
        fields.number("stream_id", entry.stream_id);
        fields.number("stream_registration", entry.stream_registration);
        fields.number("from", entry.from);
        fields.number("to", entry.to);
        fields.number("participant", entry.participant);
        fields.number("client", entry.client);
    });
}

fn guard_entry(out: &mut Out<'_>, entry: &GuardEntry) {
    out.object(|fields| {
        fields.number("seq", entry.seq);
        fields.number("time", entry.time);
        fields.number("guard", entry.guard);
        fields.number("before", entry.before);
        fields.number("after", entry.after);
        fields.number("operation", entry.operation);
        fields.number("requester_kind", entry.requester_kind);
        fields.number("requester", entry.requester);
        fields.number("outcome", entry.outcome);
        fields.number("refusal", entry.refusal);
        fields.number("operator", entry.operator);
        fields.number("parameters", entry.parameters);
    });
}

#[cfg(test)]
mod tests;

/// The bytes of a `trace-buckets` reply besides its buckets: the read
/// counts them in its bound (R-CORE-23).
pub(crate) const BUCKET_REPLY_OVERHEAD: usize = 256;

/// A `trace-buckets` reply (R-CORE-23): the run's `epoch`, the slice
/// length, the current and oldest numbers, the buckets read (the last may
/// hold part of its lanes, from `first_lane`, of `lanes_total`), and
/// `next`, `{"number","lane"}` where the next read starts, or `null` when
/// every bucket asked for is here, whole. The read bounded it.
#[must_use]
pub fn trace_buckets(read: &BucketRead) -> String {
    let mut text = String::new();
    Out(&mut text).object(|fields| {
        fields.number("epoch", read.epoch);
        fields.number("slice_ns", read.slice_ns);
        fields.number("current", read.current);
        fields.number("oldest", read.oldest);
        fields
            .key("buckets")
            .array(&read.buckets, |out, bucket| trace_bucket(out, bucket));
        fields.key("next").option(read.next, |out, next| {
            out.object(|fields| {
                fields.number("number", next.number);
                fields.number("lane", next.lane);
            });
        });
    });
    text
}

/// The bytes `bucket`'s encoding takes without its lanes: what a read
/// counts for it in the reply's bound.
#[must_use]
pub(crate) fn bucket_header_len(bucket: &TraceBucket) -> usize {
    let mut text = String::new();
    bucket_header(&mut Out(&mut text), bucket, &[]);
    text.len().saturating_add(1)
}

/// The bytes `lane`'s encoding takes in a bucket's `lanes`, with its
/// separator.
#[must_use]
pub(crate) fn bucket_lane_len(lane: &BucketLane) -> usize {
    let mut text = String::new();
    bucket_lane(&mut Out(&mut text), lane);
    text.len().saturating_add(1)
}

/// A refused `trace-buckets` read, typed (R-CORE-23).
#[must_use]
pub fn bucket_refusal(refusal: &BucketRefusal) -> String {
    let mut text = String::new();
    Out(&mut text).object(|fields| match *refusal {
        BucketRefusal::EpochChanged { epoch, oldest } => {
            fields.string("error", "epoch changed");
            fields.number("epoch", epoch);
            fields.number("oldest", oldest);
        }
        BucketRefusal::Expired { oldest } => {
            fields.string("error", "buckets expired");
            fields.number("oldest", oldest);
        }
        BucketRefusal::OverBudget { number } => {
            fields.string("error", "bucket over budget");
            fields.number("number", number);
        }
    });
    text
}

fn trace_bucket(out: &mut Out<'_>, bucket: &TraceBucket) {
    bucket_header(out, bucket, &bucket.lanes);
}

fn bucket_header(out: &mut Out<'_>, bucket: &TraceBucket, lanes: &[BucketLane]) {
    out.object(|fields| {
        fields.number("number", bucket.number);
        fields.number("start_ns", bucket.start_ns);
        fields.number("end_ns", bucket.end_ns);
        fields.key("incomplete").bool(bucket.incomplete);
        fields.key("loss").option(bucket.loss, |out, bucket_loss| {
            out.object(|loss| {
                for (key, value) in [
                    ("pending_dropped", bucket_loss.pending_dropped),
                    ("polls_dropped", bucket_loss.polls_dropped),
                    ("lanes_dropped", bucket_loss.lanes_dropped),
                    ("aged_out", bucket_loss.aged_out),
                    ("mirror_overwritten", bucket_loss.mirror_overwritten),
                    ("journals_dropped", bucket_loss.journals_dropped),
                    ("malformed", bucket_loss.malformed),
                    ("unknown_journal", bucket_loss.unknown_journal),
                ] {
                    loss.number(key, value);
                }
            });
        });
        fields.number("lanes_total", bucket.lanes_total);
        fields.number("first_lane", bucket.first_lane);
        fields
            .key("lanes")
            .array(lanes, |out, lane| bucket_lane(out, lane));
    });
}

fn bucket_lane(out: &mut Out<'_>, lane: &BucketLane) {
    out.object(|fields| {
        fields.number("stream", lane.stream);
        fields.number("incarnation", lane.incarnation);
        fields.number("lane", lane.lane);
        let counts = &lane.counts;
        fields.number("digits", counts.digits);
        fields.number("highest", counts.highest);
        fields.number("unit", counts.unit);
        fields.number("available", counts.available);
        fields
            .key("unavailable")
            .array(&counts.unavailable, |out, count| out.number(count));
        fields.key("incomplete").bool(counts.incomplete);
        for (key, side) in [("min", &counts.min), ("max", &counts.max)] {
            fields.key(key).object(|fields| {
                for (key, buckets) in [
                    ("non_negative", &side.non_negative),
                    ("negative", &side.negative),
                ] {
                    fields.key(key).array(buckets, |out, (index, count)| {
                        out.raw("[");
                        out.number(index);
                        out.raw(",");
                        out.number(count);
                        out.raw("]");
                    });
                }
                fields.number("above", side.above);
                fields.number("below", side.below);
            });
        }
    });
}

/// A `trace-export` page (R-CORE-13): the driver instance as `epoch` (32
/// lowercase hex digits, as `instance`), the sequence asked for, the lost
/// ranges first, then whole records in order, the next sequence to ask
/// for, the ring's head, the journals the records name, and how many
/// records name an unknown one. The read
/// ([`crate::trace_export::export`]) bounded the page; this encodes it
/// whole, cutting nothing.
#[must_use]
pub fn trace_export(page: &ExportPage) -> String {
    let mut text = String::new();
    Out(&mut text).object(|fields| {
        fields.string("epoch", &format!("{:032x}", page.epoch));
        fields.number("from", page.from);
        fields.key("lost").array(&page.lost, |out, loss| {
            out.object(|fields| {
                fields.number("first", loss.first);
                fields.number("last", loss.last);
                fields.string(
                    "reason",
                    match loss.reason {
                        crate::api::LossReason::Overwritten => "overwritten",
                        crate::api::LossReason::Malformed => "malformed",
                    },
                );
            });
        });
        fields
            .key("records")
            .array(&page.records, |out, record| export_record(out, record));
        fields.number("next", page.next);
        fields.number("head", page.head);
        fields
            .key("journals")
            .array(&page.journals, |out, journal| export_journal(out, journal));
        fields.key("points").array(&page.points, |out, point| {
            out.object(|fields| {
                fields.number("id", u64::from(point.id));
                fields
                    .key("label")
                    .option(point.label.as_deref(), Out::string);
                fields
                    .key("client")
                    .option(point.client, |out, client| out.number(client));
            });
        });
        fields.number("unknown_records", page.unknown_records);
        fields.number("unreadable_records", page.unreadable_records);
        let refused = page.network_journals_refused;
        fields.key("network_journals_refused").object(|fields| {
            fields
                .key("attach")
                .option(refused.attach, |out, value| out.number(value));
            fields.number("before", refused.before);
            fields.number("after", refused.after);
        });
    });
    text
}

/// The bytes of a `trace-export` reply besides its records and journals:
/// its fields, 384 bytes at most (the three `network_journals_refused`
/// reads included, karyos#931), and its overwritten ranges, at most
/// `MAX_LOST_RANGES` of at most `LOSS_BYTES` each (malformed records are
/// counted as the read meets them).
pub(crate) const EXPORT_REPLY_OVERHEAD: usize =
    384 + crate::trace_export::MAX_LOST_RANGES * crate::trace_export::LOSS_BYTES;

/// The bytes `record`'s encoding takes in a page, with its separator,
/// computed without encoding it:
/// `{"seq":S,"journal":J,"sequence":Q,"payload":[W,...]},`.
#[cfg(test)]
#[must_use]
pub(crate) fn export_record_len(record: &crate::api::ExportRecord) -> usize {
    export_record_len_of(record.seq, record.journal, record.sequence, &record.payload)
}

/// [`export_record_len`] of a record's parts, before it is built.
#[must_use]
pub(crate) fn export_record_len_of(
    seq: u64,
    journal: u64,
    sequence: u64,
    payload: &[u64],
) -> usize {
    let digits = |value: u64| value.checked_ilog10().map_or(1, |log| log as usize + 1);
    let words: usize = payload.iter().map(|word| digits(*word) + 1).sum();
    // The keys and punctuation, the payload's last word having no comma.
    r#"{"seq":,"journal":,"sequence":,"payload":[]},"#.len()
        + digits(seq)
        + digits(journal)
        + digits(sequence)
        + words.saturating_sub(usize::from(!payload.is_empty()))
}

fn export_record(out: &mut Out<'_>, record: &crate::api::ExportRecord) {
    out.object(|fields| {
        fields.number("seq", record.seq);
        fields.number("journal", record.journal);
        fields.number("sequence", record.sequence);
        fields
            .key("payload")
            .array(&record.payload, |out, word| out.number(*word));
    });
}

/// A refused `trace-export` read, typed (R-CORE-13).
#[must_use]
pub fn export_refusal(refusal: &ExportRefusal) -> String {
    let mut text = String::new();
    Out(&mut text).object(|fields| match *refusal {
        ExportRefusal::EpochChanged { epoch } => {
            fields.string("error", "epoch changed");
            fields.string("epoch", &format!("{epoch:032x}"));
        }
        ExportRefusal::Ahead { next } => {
            fields.string("error", "cursor ahead");
            fields.number("next", next);
        }
        ExportRefusal::Busy => fields.string("error", "mirror busy"),
    });
    text
}

fn export_journal(out: &mut Out<'_>, journal: &ExportJournal) {
    use karyos_sys::trace_mirror::{JournalKind, JournalState, TimeNamespace};

    let state = |state: JournalState| match state {
        JournalState::Open => "open",
        JournalState::Closed => "closed",
        JournalState::WriterLost => "writer_lost",
    };
    out.object(|fields| match journal {
        ExportJournal::Live(entry) => {
            fields.number("journal", entry.journal);
            fields.string("table", "live");
            fields.number("client", entry.client);
            fields.string("state", state(entry.state));
            fields.string(
                "kind",
                match entry.kind {
                    JournalKind::Subscriber => "subscriber",
                    JournalKind::Publisher => "publisher",
                    JournalKind::NetworkSender => "network_sender",
                    JournalKind::NetworkReceiver => "network_receiver",
                },
            );
            fields.number("registration", entry.registration);
            fields.number("stream", entry.stream);
            fields.number("lane", u64::from(entry.lane.get()));
            fields.number("incarnation", entry.incarnation);
            fields.string(
                "time_namespace",
                match entry.time_namespace {
                    TimeNamespace::Unknown => "unknown",
                    TimeNamespace::Same => "same",
                    TimeNamespace::Different => "different",
                },
            );
            fields.number("provenance", entry.provenance);
            fields
                .key("join")
                .option(entry.join, |out, value| out.number(value));
            if entry.kind.is_network() {
                // NT-4: a fact whose validity flag is clear is unknown,
                // `null`, never 0 (karyos#931).
                // No facts at all (an entry the driver has not filled) is
                // `null` too.
                fields.key("network").option(entry.network, |out, facts| {
                    out.object(|fields| {
                        fields
                            .key("sender_driver")
                            .array(&facts.sender_driver, |out, word| {
                                out.number(*word);
                            });
                        fields
                            .key("start")
                            .option(facts.start, |out, value| out.number(value));
                        fields
                            .key("boundary")
                            .option(facts.boundary, |out, value| out.number(value));
                        fields
                            .key("first_gap")
                            .option(facts.first_gap, |out, value| out.number(value));
                    });
                });
            }
            fields.number("payload_words", entry.payload_words);
            fields.number("sequence", entry.sequence);
            fields.number("attempted", entry.attempted);
            fields.number("stored", entry.stored);
            fields.number("mirrored", entry.mirrored);
            fields
                .key("lost_before")
                .option(entry.lost_before, |out, value| out.number(value));
            fields.number("unstable", entry.unstable);
            fields.key("drops").array(entry.ranges(), |out, range| {
                out.object(|fields| {
                    fields.number("first", range.first);
                    fields.number("last", range.last);
                    fields.number("first_time", range.first_time);
                    fields.number("last_time", range.last_time);
                    fields.number("clock", range.clock);
                    fields.number("epoch", range.epoch);
                });
            });
        }
        ExportJournal::Recycled(entry) => {
            fields.number("journal", entry.journal);
            fields.string("table", "recycled");
            fields.string("state", state(entry.state));
            fields.number("stream", entry.stream);
            fields.number("lane", u64::from(entry.lane.get()));
            fields.number("incarnation", entry.incarnation);
            fields
                .key("boundary")
                .option(entry.boundary, |out, value| out.number(value));
            fields.number("sequence", entry.sequence);
        }
        ExportJournal::Unknown { journal } => {
            fields.number("journal", *journal);
            fields.string("table", "unknown");
        }
        ExportJournal::Unreadable { journal } => {
            fields.number("journal", *journal);
            fields.string("table", "unreadable");
        }
    });
}

/// A registry write's answer (karyos#736): `{"registered":{...}}` or
/// `{"retired":{...}}`, naming the version.
#[must_use]
pub fn join_written(
    retired: bool,
    dir: &std::path::Path,
    kind: crate::registry::Kind,
    key: &str,
    version: u64,
    generation: u64,
) -> String {
    let mut text = String::new();
    Out(&mut text).object(|fields| {
        fields
            .key(if retired { "retired" } else { "registered" })
            .object(|fields| {
                fields.string("driver", &dir.to_string_lossy());
                fields.string("kind", kind.name());
                fields.string("key", key);
                fields.number("version", version);
                fields.number("generation", generation);
            });
    });
    text
}

/// A registry request's refusal: past a bound in the shape of
/// [`above_bound`], a malformed argument as `bad arguments` with what was
/// wrong, no current entry, or an unknown driver.
#[must_use]
pub fn join_refusal(request: &str, error: crate::registry::JoinError) -> String {
    use crate::registry::{JoinError, Refusal};
    match error {
        JoinError::Refused(Refusal::Above { dimension, bound }) => {
            above_bound(&crate::api::Limit {
                name: dimension,
                bound: Some(bound),
                negotiable: false,
            })
        }
        JoinError::Refused(Refusal::Bad(what)) => {
            let mut text = String::new();
            Out(&mut text).object(|fields| {
                fields.string("error", "bad arguments");
                fields.string("request", request);
                fields.string("detail", what);
            });
            text
        }
        JoinError::Refused(Refusal::NotFound) => error_text("no such entry"),
        JoinError::Refused(Refusal::Overflow(counter)) => {
            let mut text = String::new();
            Out(&mut text).object(|fields| {
                fields.string("error", "counter overflow");
                fields.string("request", request);
                fields.string("detail", counter);
            });
            text
        }
        JoinError::UnknownDriver => error_text("unknown driver"),
    }
}

/// `{"error": message}`.
fn error_text(message: &str) -> String {
    error(message, None)
}

/// A `join-get` answer: `{"join":{...}}` with the version in force at
/// `at`, or `null`.
#[must_use]
pub fn join_read(read: &crate::registry::Read<'_>) -> String {
    let mut text = String::new();
    Out(&mut text).object(|fields| {
        fields.key("join").object(|fields| {
            fields.number("generation", read.generation);
            fields.number("since_ns", read.since_ns);
            fields.string("driver", &read.dir.to_string_lossy());
            fields.string("kind", read.kind.name());
            fields.string("key", read.key);
            fields.number("at", read.at);
            presence(fields, read.presence);
            fields
                .key("version")
                .option(read.entry.and_then(|entry| entry.at(read.at)), join_version);
            fields.number(
                "history_dropped",
                read.entry.map_or(0, |entry| entry.history_dropped),
            );
            fields.key("before_history").bool(
                read.entry
                    .is_some_and(|entry| entry.before_history(read.at)),
            );
        });
    });
    text
}

/// A `join-list` page: `{"join_list":{...}}`.
#[must_use]
pub fn join_page(page: &crate::registry::Page<'_>) -> String {
    let mut text = String::new();
    Out(&mut text).object(|fields| {
        fields.key("join_list").object(|fields| {
            fields.number("generation", page.generation);
            fields.number("since_ns", page.since_ns);
            fields.number("evicted", page.evicted);
            fields.string("driver", &page.dir.to_string_lossy());
            fields
                .key("entries")
                .array(&page.entries, |out, (entry, seen)| {
                    out.object(|fields| {
                        fields.string("kind", entry.kind.name());
                        fields.string("key", &entry.key);
                        presence(fields, *seen);
                        fields.number("history_dropped", entry.history_dropped);
                        fields
                            .key("retired_ns")
                            .option(entry.retired_ns, |out, at| out.number(at));
                        let versions: Vec<_> = entry.versions.iter().collect();
                        fields
                            .key("versions")
                            .array(&versions, |out, version| join_version(out, version));
                    });
                });
            fields.key("more").bool(page.more);
        });
    });
    text
}

/// What the agent observes of an identity: `present`, `holders` and
/// `shared`, each `null` when it cannot tell.
fn presence(fields: &mut Fields<'_, '_>, seen: crate::registry::Presence) {
    fields.key("present").option(seen.present, Out::bool);
    fields
        .key("holders")
        .option(seen.holders, |out, holders| out.number(holders));
    fields.key("shared").option(seen.shared(), Out::bool);
}

/// One version: its number, uid, validity and attributes as an object.
fn join_version(out: &mut Out<'_>, version: &crate::registry::Version) {
    out.object(|fields| {
        fields.number("number", version.number);
        fields.number("registered_by", version.registered_by);
        // The relay that carried the put (karyos#708), apart; null for a
        // put on the local socket.
        fields.key("relay").option(
            (version.relay != 0).then_some(version.relay),
            |out, relay| {
                out.number(relay);
            },
        );
        fields.number("valid_from", version.valid_from);
        fields
            .key("valid_to")
            .option(version.valid_to, |out, to| out.number(to));
        fields.key("attributes").object(|fields| {
            for (name, value) in version.attributes() {
                fields.string(name, value);
            }
        });
    });
}
