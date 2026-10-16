// SPDX-License-Identifier: Apache-2.0

//! Channel URI parsing: the SPEC.md §5 examples, every parameter's range,
//! and every refusal.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use super::*;

fn udp(uri: &str) -> UdpConfig {
    match ChannelConfig::parse(uri).unwrap().media {
        Media::Udp(udp) => udp,
        Media::Ipc => panic!("not udp: {uri}"),
    }
}

fn refused(uri: &str) -> ChannelError {
    ChannelConfig::parse(uri).unwrap_err()
}

fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

/// The URIs SPEC.md §5 lists parse to what they say.
#[test]
fn the_spec_examples_parse() {
    let ipc = ChannelConfig::parse("karyos:ipc").unwrap();
    assert_eq!(ipc.media, Media::Ipc);
    assert_eq!(ipc.common, CommonConfig::default());

    let unicast = udp("karyos:udp?endpoint=10.0.0.5:40123|interface=eth1");
    assert_eq!(
        unicast.destination,
        Destination::Unicast(addr("10.0.0.5:40123"))
    );
    assert_eq!(unicast.interface, Some(Interface::Name("eth1".into())));
    assert!(unicast.reliable);
    assert_eq!(unicast.security, Security::Trusted);

    let multicast = udp("karyos:udp?group=239.1.1.1:40456|interface=eth1|ttl=1");
    assert_eq!(
        multicast.destination,
        Destination::Multicast {
            group: addr("239.1.1.1:40456"),
            ttl: Some(1)
        }
    );

    let fixed = udp("karyos:udp?destinations=10.0.0.5:40123;10.0.0.6:40123");
    assert_eq!(
        fixed.destination,
        Destination::MultiDestination {
            destinations: vec![addr("10.0.0.5:40123"), addr("10.0.0.6:40123")],
            control: None,
            mode: ControlMode::Manual,
        }
    );

    let dynamic = udp("karyos:udp?control=10.0.0.1:40200|control-mode=dynamic");
    assert_eq!(
        dynamic.destination,
        Destination::MultiDestination {
            destinations: vec![],
            control: Some(addr("10.0.0.1:40200")),
            mode: ControlMode::Dynamic,
        }
    );

    let config =
        ChannelConfig::parse("karyos:udp?endpoint=10.0.0.5:40123|lanes=2|guard=orders").unwrap();
    assert_eq!(config.common.lanes, Some(2));
    assert_eq!(config.common.guard.as_deref(), Some("orders"));
}

/// The common parameters apply to `ipc` too, each within its range.
#[test]
fn common_parameters_are_checked() {
    let config =
        ChannelConfig::parse("karyos:ipc?mtu=8192|term-length=65536|lanes=4|trace=sampled:100")
            .unwrap();
    assert_eq!(config.common.mtu, Some(8192));
    assert_eq!(config.common.term_length.map(TermLength::get), Some(65536));
    assert_eq!(config.common.lanes, Some(4));
    assert_eq!(config.common.trace, Trace::Sampled(100));
    for (uri, key) in [
        ("karyos:ipc?mtu=8193", "mtu"),
        ("karyos:ipc?mtu=32", "mtu"),
        ("karyos:ipc?mtu=01408", "mtu"),
        ("karyos:ipc?mtu=+1408", "mtu"),
        ("karyos:ipc?term-length=65537", "term-length"),
        ("karyos:ipc?term-length=32768", "term-length"),
        ("karyos:ipc?lanes=0", "lanes"),
        ("karyos:ipc?lanes=5", "lanes"),
        ("karyos:ipc?trace=sampled:0", "trace"),
        ("karyos:ipc?trace=sometimes", "trace"),
    ] {
        assert!(
            matches!(refused(uri), ChannelError::InvalidValue { key: found, .. } if found == key),
            "{uri}"
        );
    }
    assert!(matches!(
        refused(&format!("karyos:ipc?guard={}", "g".repeat(65))),
        ChannelError::InvalidValue { key: "guard", .. }
    ));
    for name in ["or ders", "orders;x", "ordérs", "a/b"] {
        assert!(
            matches!(
                refused(&format!("karyos:ipc?guard={name}")),
                ChannelError::InvalidValue { key: "guard", .. }
            ),
            "{name}"
        );
    }
    assert_eq!(
        ChannelConfig::parse("karyos:ipc?guard=Desk_1.orders-A")
            .unwrap()
            .common
            .guard
            .as_deref(),
        Some("Desk_1.orders-A")
    );
    assert_eq!(
        ChannelConfig::parse("karyos:ipc?trace=all")
            .unwrap()
            .common
            .trace,
        Trace::All
    );
}

/// A UDP channel names exactly one destination.
#[test]
fn a_udp_channel_needs_exactly_one_destination() {
    for uri in [
        "karyos:udp",
        "karyos:udp?interface=eth1",
        "karyos:udp?endpoint=10.0.0.5:1|group=239.1.1.1:1",
        "karyos:udp?endpoint=10.0.0.5:1|destinations=10.0.0.6:1",
        "karyos:udp?group=239.1.1.1:1|control=10.0.0.1:2",
    ] {
        assert_eq!(refused(uri), ChannelError::Destination, "{uri}");
    }
}

/// Addresses: a group must be multicast, an endpoint must not, no port 0,
/// no unspecified address; IPv6 parses.
#[test]
fn addresses_are_checked() {
    for (uri, key) in [
        ("karyos:udp?endpoint=239.1.1.1:1", "endpoint"),
        ("karyos:udp?group=10.0.0.5:1", "group"),
        ("karyos:udp?endpoint=10.0.0.5:0", "endpoint"),
        ("karyos:udp?endpoint=0.0.0.0:1", "endpoint"),
        ("karyos:udp?endpoint=10.0.0.5", "endpoint"),
        ("karyos:udp?endpoint=host:1", "endpoint"),
        (
            "karyos:udp?destinations=10.0.0.5:1;10.0.0.5:1",
            "destinations",
        ),
        (
            "karyos:udp?destinations=10.0.0.5:1;239.1.1.1:1",
            "destinations",
        ),
    ] {
        assert!(
            matches!(refused(uri), ChannelError::InvalidValue { key: found, .. } if found == key),
            "{uri}"
        );
    }
    assert_eq!(
        udp("karyos:udp?endpoint=[::1]:40123").destination,
        Destination::Unicast(addr("[::1]:40123"))
    );
    let many = (1..=65)
        .map(|n| format!("10.0.0.{n}:1"))
        .collect::<Vec<_>>()
        .join(";");
    assert!(matches!(
        refused(&format!("karyos:udp?destinations={many}")),
        ChannelError::InvalidValue {
            key: "destinations",
            ..
        }
    ));
}

/// Parameters outside their channel are refused, not ignored.
#[test]
fn parameters_apply_only_where_they_mean_something() {
    for (uri, key) in [
        ("karyos:ipc?endpoint=10.0.0.5:1", "endpoint"),
        ("karyos:ipc?reliable=false", "reliable"),
        ("karyos:udp?endpoint=10.0.0.5:1|ttl=1", "ttl"),
        ("karyos:udp?endpoint=10.0.0.5:1|fc=min", "fc"),
        (
            "karyos:udp?group=239.1.1.1:1|control-mode=manual",
            "control-mode",
        ),
    ] {
        assert!(
            matches!(refused(uri), ChannelError::NotApplicable { key: found } if found == key),
            "{uri}"
        );
    }
    let multicast = udp("karyos:udp?group=239.1.1.1:1|fc=tagged:7");
    assert_eq!(multicast.flow_control, Some(FlowControl::Tagged(7)));
    assert_eq!(
        udp("karyos:udp?destinations=10.0.0.5:1|fc=max").flow_control,
        Some(FlowControl::Max)
    );
}

/// Multi-destination modes: dynamic needs a control endpoint, manual needs
/// a list.
#[test]
fn control_modes_are_consistent() {
    assert!(matches!(
        refused("karyos:udp?destinations=10.0.0.5:1|control-mode=dynamic"),
        ChannelError::Conflict { .. }
    ));
    assert!(matches!(
        refused("karyos:udp?control=10.0.0.1:2|control-mode=manual"),
        ChannelError::Conflict { .. }
    ));
    let both = udp("karyos:udp?destinations=10.0.0.5:1|control=10.0.0.1:2|control-mode=manual");
    assert!(matches!(
        both.destination,
        Destination::MultiDestination {
            mode: ControlMode::Manual,
            control: Some(_),
            ..
        }
    ));
}

/// Interfaces and paths.
#[test]
fn interfaces_and_paths_are_checked() {
    let paths = udp("karyos:udp?endpoint=10.0.0.5:1|paths=eth1;eth2;192.168.1.2");
    assert_eq!(
        paths.paths,
        vec![
            Interface::Name("eth1".into()),
            Interface::Name("eth2".into()),
            Interface::Address("192.168.1.2".parse().unwrap()),
        ]
    );
    for uri in [
        "karyos:udp?endpoint=10.0.0.5:1|paths=eth1;eth1",
        "karyos:udp?endpoint=10.0.0.5:1|paths=a;b;c;d;e",
        "karyos:udp?endpoint=10.0.0.5:1|interface=eth 1",
        "karyos:udp?endpoint=10.0.0.5:1|interface=averyveryverylongname",
        "karyos:udp?endpoint=10.0.0.5:1|interface=239.1.1.1",
    ] {
        assert!(
            matches!(refused(uri), ChannelError::InvalidValue { .. }),
            "{uri}"
        );
    }
    assert!(matches!(
        refused("karyos:udp?endpoint=10.0.0.5:1|interface=eth0|paths=eth1;eth2"),
        ChannelError::Conflict { .. }
    ));
}

/// Phase 2: only `trusted`.
#[test]
fn only_trusted_security_is_supported() {
    assert_eq!(
        udp("karyos:udp?endpoint=10.0.0.5:1|security=trusted").security,
        Security::Trusted
    );
    for class in ["authenticated", "encrypted"] {
        assert_eq!(
            refused(&format!("karyos:udp?endpoint=10.0.0.5:1|security={class}")),
            ChannelError::SecurityUnsupported { class }
        );
    }
    assert!(matches!(
        refused("karyos:udp?endpoint=10.0.0.5:1|security=plain"),
        ChannelError::InvalidValue {
            key: "security",
            ..
        }
    ));
    assert!(!udp("karyos:udp?endpoint=10.0.0.5:1|reliable=false").reliable);
}

/// Syntax refusals: scheme, media, malformed, unknown, repeated, too long.
#[test]
fn malformed_uris_are_refused() {
    for uri in [
        "udp?endpoint=10.0.0.5:1",
        "karyos:tcp",
        "karyos:",
        "karyos:udpx",
    ] {
        assert_eq!(refused(uri), ChannelError::UnknownMedia, "{uri}");
    }
    for uri in [
        "karyos:udp?endpoint",
        "karyos:udp?endpoint=",
        "karyos:udp?endpoint=10.0.0.5:1|",
        "karyos:ipc?",
    ] {
        assert!(
            matches!(refused(uri), ChannelError::Malformed { .. }),
            "{uri}"
        );
    }
    assert_eq!(
        refused("karyos:udp?endpoint=10.0.0.5:1|mtus=1408"),
        ChannelError::UnknownParameter { key: "mtus".into() }
    );
    assert_eq!(
        refused("karyos:udp?endpoint=10.0.0.5:1|lanes=1|lanes=2"),
        ChannelError::Repeated { key: "lanes" }
    );
    let long = format!("karyos:ipc?guard={}", "g".repeat(MAX_URI_LENGTH));
    assert!(matches!(refused(&long), ChannelError::TooLong { .. }));
}

proptest::proptest! {
    /// Any text parses or is refused, never panics; a URI built from
    /// arbitrary parameter fragments is handled the same way.
    #[test]
    fn arbitrary_text_never_panics(text in ".{0,300}") {
        let _ = ChannelConfig::parse(&text);
        let _ = ChannelConfig::parse(&format!("karyos:udp?{text}"));
    }

    #[test]
    fn arbitrary_parameters_never_panic(
        keys in proptest::collection::vec(
            proptest::sample::select(KEYS.iter().map(|(name, _)| *name).collect::<Vec<_>>()),
            0..6,
        ),
        values in proptest::collection::vec("[0-9a-z.:;\\[\\]=-]{0,24}", 6),
    ) {
        let query = keys
            .iter()
            .zip(&values)
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("|");
        let _ = ChannelConfig::parse(&format!("karyos:udp?{query}"));
        let _ = ChannelConfig::parse(&format!("karyos:ipc?{query}"));
    }
}
