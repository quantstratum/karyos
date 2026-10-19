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
//!   (`"attached"`, `"closed"`, `"unavailable"`) and its variant's fields.

use std::fmt::Write;

use crate::api::{
    AgentView, Counter, DriverState, DriverView, ErrorEntry, Feed, GuardEntry, Lane, LossEntry,
    Sample, Subscriber,
};

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
        fields.number("value", counter.value);
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
    });
}

fn subscriber_json(out: &mut Out<'_>, subscriber: &Subscriber) {
    out.object(|fields| {
        fields.number("registration", subscriber.registration);
        fields.string("label", &subscriber.label);
        fields.number("position", subscriber.position);
        fields
            .key("lag")
            .option(subscriber.lag, |out, value| out.number(value));
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
    });
}

#[cfg(test)]
mod tests;
