// SPDX-License-Identifier: Apache-2.0

//! The startup capability log of `karyosd` (SPEC §11, "logged at
//! startup"; quantstratum-docs: karyos/design/management-agent-gap-analysis.md,
//! M3b): each network endpoint's capability gauges (M3), read as one group
//! from the daemon's own CnC, written as one line when the endpoint first
//! appears and again at each new capability epoch.
//!
//! [`line()`] names every capability and its state:
//!
//! - a value gauge as `name=value`, with the platform, copy mode and queue
//!   assignment by name (`platform=linux`);
//! - a state gauge as `name=state`, with its reason and the reason's detail
//!   (an OS error number, or the effective value below the request) when
//!   there is one: `gso=unavailable(library_api)`,
//!   `send_buffer=fallback(below_request,212992)`;
//! - a gauge this version does not know as `name=value`.
//!
//! Names are the gauge labels without `capability `, spaces as `_`.

/// The value gauges, in the order the line gives them.
const VALUES: [&str; 9] = [
    "capability epoch",
    "capability platform",
    "capability copy mode",
    "capability queue assignment",
    "capability max datagram",
    "capability observation points",
    "capability clock granularity",
    "capability send buffer bytes",
    "capability recv buffer bytes",
];

/// The state gauges, in the order the line gives them.
const STATES: [&str; 11] = [
    "capability dont fragment",
    "capability tx batch",
    "capability rx batch",
    "capability gso",
    "capability gro",
    "capability kernel stamps",
    "capability hardware stamps",
    "capability busy poll",
    "capability user observations",
    "capability send buffer",
    "capability recv buffer",
];

/// The label of the gauge that holds the capability epoch.
pub const EPOCH: &str = "capability epoch";

/// The log line of an endpoint whose capability gauges are `gauges`
/// (label and value): the value gauges, then the state gauges, then any
/// other, each as the module describes.
#[must_use]
pub fn line(gauges: &[(String, u64)]) -> String {
    let value = |label: &str| {
        gauges
            .iter()
            .find(|(name, _)| name == label)
            .map(|(_, value)| *value)
    };
    let mut fields = Vec::with_capacity(gauges.len());
    for label in VALUES {
        if let Some(raw) = value(label) {
            fields.push(format!("{}={}", name(label), shown_value(label, raw)));
        }
    }
    for label in STATES {
        if let Some(raw) = value(label) {
            fields.push(format!("{}={}", name(label), state(raw)));
        }
    }
    for (label, raw) in gauges {
        if !VALUES.contains(&label.as_str()) && !STATES.contains(&label.as_str()) {
            fields.push(format!("{}={raw}", name(label)));
        }
    }
    fields.join(" ")
}

/// A label without `capability `, spaces as `_`.
fn name(label: &str) -> String {
    label
        .strip_prefix("capability ")
        .unwrap_or(label)
        .replace(' ', "_")
}

/// A value gauge, by name where it is an enumeration.
fn shown_value(label: &str, raw: u64) -> String {
    let named = match (label, raw) {
        ("capability platform", 1) => "linux",
        ("capability platform", 2) => "macos",
        ("capability copy mode", 1) => "staged",
        ("capability queue assignment", 1) => "kernel_selected",
        _ => return raw.to_string(),
    };
    named.to_owned()
}

/// A state gauge: the state in bits 7 to 0, the reason in bits 15 to 8 and
/// the reason's detail in bits 63 to 32 (observability-and-tools.md,
/// Endpoint capabilities).
fn state(raw: u64) -> String {
    let [code, reason, ..] = raw.to_le_bytes();
    let detail = raw >> 32;
    let state = match code {
        0 => "not_requested".to_owned(),
        1 => "active".to_owned(),
        2 => "fallback".to_owned(),
        3 => "unavailable".to_owned(),
        other => format!("state_{other}"),
    };
    let reason = match reason {
        0 => None,
        1 => Some("not_built".to_owned()),
        2 => Some("platform".to_owned()),
        3 => Some("library_api".to_owned()),
        4 => Some("unsupported".to_owned()),
        5 => Some("denied".to_owned()),
        6 => Some("probe_failed".to_owned()),
        7 => Some("below_request".to_owned()),
        8 => Some("unverified".to_owned()),
        other => Some(format!("reason_{other}")),
    };
    match (reason, detail) {
        (None, 0) => state,
        (None, detail) => format!("{state}({detail})"),
        (Some(reason), 0) => format!("{state}({reason})"),
        (Some(reason), detail) => format!("{state}({reason},{detail})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gauges(pairs: &[(&str, u64)]) -> Vec<(String, u64)> {
        pairs
            .iter()
            .map(|(label, value)| ((*label).to_owned(), *value))
            .collect()
    }

    /// Every capability of an endpoint's snapshot is named with its state,
    /// values first, whatever the order the gauges came in.
    #[test]
    fn the_line_names_every_capability_and_its_state() {
        let mut all: Vec<(&str, u64)> = vec![
            ("capability epoch", 3),
            ("capability platform", 1),
            ("capability copy mode", 1),
            ("capability queue assignment", 1),
            ("capability max datagram", 65_507),
            ("capability observation points", 3),
            ("capability clock granularity", 1),
            ("capability send buffer bytes", 212_992),
            ("capability recv buffer bytes", 0),
            ("capability dont fragment", 1),
            ("capability tx batch", 0),
            ("capability rx batch", 2 | 4 << 8),
            ("capability gso", 3 | 3 << 8),
            ("capability gro", 3 | 2 << 8),
            ("capability kernel stamps", 3 | 6 << 8 | 95 << 32),
            ("capability hardware stamps", 0),
            ("capability busy poll", 3 | 5 << 8 | 1 << 32),
            ("capability user observations", 1),
            ("capability send buffer", 2 | 7 << 8 | 212_992 << 32),
            ("capability recv buffer", 3 | 8 << 8),
        ];
        all.reverse();
        assert_eq!(
            line(&gauges(&all)),
            "epoch=3 platform=linux copy_mode=staged queue_assignment=kernel_selected \
             max_datagram=65507 observation_points=3 clock_granularity=1 \
             send_buffer_bytes=212992 recv_buffer_bytes=0 dont_fragment=active \
             tx_batch=not_requested rx_batch=fallback(unsupported) \
             gso=unavailable(library_api) gro=unavailable(platform) \
             kernel_stamps=unavailable(probe_failed,95) hardware_stamps=not_requested \
             busy_poll=unavailable(denied,1) user_observations=active \
             send_buffer=fallback(below_request,212992) recv_buffer=unavailable(unverified)"
        );
        for (label, _) in &all {
            let named = name(label);
            assert!(
                line(&gauges(&all)).contains(&format!("{named}=")),
                "{label}"
            );
        }
    }

    /// Codes this version does not know are shown by number, and a gauge it
    /// does not know by its raw value, never dropped.
    #[test]
    fn unknown_codes_and_gauges_are_kept() {
        assert_eq!(
            line(&gauges(&[
                ("capability platform", 9),
                ("capability gso", 7 | 12 << 8),
                ("capability launch time", 1),
            ])),
            "platform=9 gso=state_7(reason_12) launch_time=1"
        );
        assert_eq!(line(&[]), "");
    }
}
