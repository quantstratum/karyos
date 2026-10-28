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
        fields.key("loss").object(|loss| {
            for (key, value) in [
                ("pending_dropped", bucket.loss.pending_dropped),
                ("polls_dropped", bucket.loss.polls_dropped),
                ("lanes_dropped", bucket.loss.lanes_dropped),
                ("aged_out", bucket.loss.aged_out),
                ("mirror_overwritten", bucket.loss.mirror_overwritten),
                ("journals_dropped", bucket.loss.journals_dropped),
                ("malformed", bucket.loss.malformed),
                ("unknown_journal", bucket.loss.unknown_journal),
            ] {
                loss.number(key, value);
            }
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
