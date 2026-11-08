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

/// The sixteen keys published before the common URI rule, as SPEC.md §5
/// and the alpha.2 parser spell them. Frozen: a key may be added to
/// [`KEYS`], never renamed or removed from this list.
const PUBLISHED_KEYS: [&str; 16] = [
    "endpoint",
    "group",
    "interface",
    "mtu",
    "term-length",
    "reliable",
    "paths",
    "lanes",
    "guard",
    "trace",
    "fc",
    "security",
    "destinations",
    "control",
    "control-mode",
    "ttl",
];

/// Every key of [`KEYS`] still parses to the meaning it had, one case per
/// key, enumerated from the table so that no key is left out; and every
/// published key is still in the table under the same spelling.
#[test]
fn published_keys_keep_their_meaning() {
    for published in PUBLISHED_KEYS {
        assert!(
            KEYS.iter().any(|(name, _)| *name == published),
            "published key `{published}` is gone"
        );
    }
    for (name, key) in KEYS {
        match key {
            Key::Endpoint => assert_eq!(
                udp("karyos:udp?endpoint=[fe80::1%2]:40123").destination,
                Destination::Unicast(addr("[fe80::1%2]:40123"))
            ),
            Key::Group => assert_eq!(
                udp("karyos:udp?group=[ff02::1]:40456").destination,
                Destination::Multicast {
                    group: addr("[ff02::1]:40456"),
                    ttl: None
                }
            ),
            Key::Interface => assert_eq!(
                udp("karyos:udp?endpoint=10.0.0.5:1|interface=fe80::1").interface,
                Some(Interface::Address("fe80::1".parse().unwrap()))
            ),
            Key::Mtu => assert_eq!(
                ChannelConfig::parse("karyos:ipc?mtu=1408")
                    .unwrap()
                    .common
                    .mtu,
                Some(1408)
            ),
            Key::TermLength => assert_eq!(
                ChannelConfig::parse("karyos:ipc?term-length=1073741824")
                    .unwrap()
                    .common
                    .term_length
                    .map(TermLength::get),
                Some(1 << 30)
            ),
            // Not the default, so an ignored key would fail.
            Key::Reliable => {
                assert!(!udp("karyos:udp?endpoint=10.0.0.5:1|reliable=false").reliable)
            }
            Key::Paths => assert_eq!(
                udp("karyos:udp?group=239.1.1.1:1|paths=eth1;::1").paths,
                vec![
                    Interface::Name("eth1".into()),
                    Interface::Address("::1".parse().unwrap())
                ]
            ),
            Key::Lanes => assert_eq!(
                ChannelConfig::parse("karyos:ipc?lanes=1")
                    .unwrap()
                    .common
                    .lanes,
                Some(1)
            ),
            Key::Guard => assert_eq!(
                ChannelConfig::parse("karyos:ipc?guard=a")
                    .unwrap()
                    .common
                    .guard
                    .as_deref(),
                Some("a")
            ),
            Key::Trace => assert_eq!(
                ChannelConfig::parse("karyos:ipc?trace=off")
                    .unwrap()
                    .common
                    .trace,
                Trace::Off
            ),
            Key::Fc => assert_eq!(
                udp("karyos:udp?group=239.1.1.1:1|fc=tagged:0").flow_control,
                Some(FlowControl::Tagged(0))
            ),
            Key::Security => assert_eq!(
                udp("karyos:udp?group=239.1.1.1:1|security=trusted").security,
                Security::Trusted
            ),
            Key::Destinations => assert_eq!(
                udp("karyos:udp?destinations=[::ffff:10.0.0.5]:1;10.0.0.6:1").destination,
                Destination::MultiDestination {
                    destinations: vec![addr("[::ffff:10.0.0.5]:1"), addr("10.0.0.6:1")],
                    control: None,
                    mode: ControlMode::Manual,
                }
            ),
            Key::Control => assert_eq!(
                udp("karyos:udp?control=[::1]:40200").destination,
                Destination::MultiDestination {
                    destinations: vec![],
                    control: Some(addr("[::1]:40200")),
                    mode: ControlMode::Dynamic,
                }
            ),
            Key::ControlMode => assert!(matches!(
                udp("karyos:udp?control=10.0.0.1:2|control-mode=dynamic|destinations=10.0.0.5:1")
                    .destination,
                Destination::MultiDestination {
                    mode: ControlMode::Dynamic,
                    ..
                }
            )),
            // The `u8` syntax `ttl` predates the decimal rule with
            // (CHANNEL-URI.md section 4): a published leniency.
            Key::Ttl => assert_eq!(
                udp("karyos:udp?group=239.1.1.1:1|ttl=+01").destination,
                Destination::Multicast {
                    group: addr("239.1.1.1:1"),
                    ttl: Some(1)
                }
            ),
            Key::RetransmitWindow => assert_eq!(
                udp("karyos:udp?endpoint=10.0.0.5:1|retransmit-window=4096").retransmit_window,
                Some(4096)
            ),
        }
        assert_eq!(key.name(), name);
    }
}

/// The grammar file names every key of [`KEYS`] in its key table.
#[test]
fn the_grammar_file_lists_every_key() {
    let grammar = include_str!("../../CHANNEL-URI.md");
    for (name, _) in KEYS {
        assert!(
            grammar.contains(&format!("\n| `{name}` |")),
            "CHANNEL-URI.md has no row for `{name}`"
        );
    }
}

/// Key names: kebab-case, one spelling, case sensitive.
#[test]
fn keys_are_kebab_case_with_one_spelling() {
    assert!(keys_follow_the_naming_rule());
    // Each word starts with a letter: `a1-b2` is a key name, `a-1b` is
    // not (CHANNEL-URI.md section 2).
    for name in [
        "mtu",
        "term-length",
        "path-skew",
        "retransmit-window",
        "a1-b2",
    ] {
        assert!(kebab_case(name), "{name}");
    }
    for name in [
        "",
        "-",
        "Mtu",
        "term_length",
        "-mtu",
        "mtu-",
        "term--length",
        "1mtu",
        "a-1b",
        "pàth",
    ] {
        assert!(!kebab_case(name), "{name}");
    }
    for uri in [
        "karyos:ipc?term_length=65536",
        "karyos:ipc?MTU=1408",
        "karyos:ipc?Lanes=2",
    ] {
        assert!(
            matches!(refused(uri), ChannelError::UnknownParameter { .. }),
            "{uri}"
        );
    }
    // A repetition is refused even when the values agree.
    assert_eq!(
        refused("karyos:ipc?lanes=2|lanes=2"),
        ChannelError::Repeated { key: "lanes" }
    );
}

/// The duration grammar: a canonical decimal and a unit, converted with
/// checked arithmetic.
#[test]
fn durations_follow_the_grammar() {
    for (text, nanos) in [
        ("0s", 0),
        ("5s", 5_000_000_000),
        ("1ms", 1_000_000),
        ("250us", 250_000),
        ("7ns", 7),
        ("1000ms", 1_000_000_000),
        ("18446744073s", 18_446_744_073_000_000_000),
        ("18446744073709551615ns", u64::MAX),
    ] {
        assert_eq!(
            parse_duration(text),
            Ok(Duration::from_nanos(nanos)),
            "{text}"
        );
    }
    for (text, error) in [
        ("5", DurationError::MissingUnit),
        ("0", DurationError::MissingUnit),
        ("5m", DurationError::UnknownUnit),
        ("5min", DurationError::UnknownUnit),
        ("5sec", DurationError::UnknownUnit),
        ("5S", DurationError::UnknownUnit),
        ("5µs", DurationError::UnknownUnit),
        ("5 s", DurationError::UnknownUnit),
        ("1.5s", DurationError::UnknownUnit),
        ("1e3ms", DurationError::UnknownUnit),
        ("5s5", DurationError::UnknownUnit),
        ("", DurationError::NotDecimal),
        ("ms", DurationError::NotDecimal),
        ("05s", DurationError::NotDecimal),
        ("+5s", DurationError::NotDecimal),
        ("-5s", DurationError::NotDecimal),
        ("99999999999s", DurationError::Overflow),
        ("18446744074s", DurationError::Overflow),
        ("18446744073709551616ns", DurationError::Overflow),
        ("99999999999999999999999999s", DurationError::Overflow),
    ] {
        assert_eq!(parse_duration(text), Err(error), "{text}");
    }
    assert_eq!(
        ChannelError::InvalidDuration {
            key: "linger",
            error: DurationError::MissingUnit
        }
        .code(),
        11
    );
}

/// IPv6 and address forms as CHANNEL-URI.md section 4 records them.
#[test]
fn address_forms_follow_the_grammar() {
    assert_eq!(
        udp("karyos:udp?endpoint=10.0.0.5:040123").destination,
        Destination::Unicast(addr("10.0.0.5:40123"))
    );
    for uri in [
        "karyos:udp?endpoint=::1:40123",
        "karyos:udp?endpoint=[fe80::1%eth0]:40123",
        "karyos:udp?endpoint=[::]:1",
        "karyos:udp?endpoint=[::1]:0",
        "karyos:udp?endpoint=010.0.0.5:1",
        "karyos:udp?endpoint=10.0.0.5:1|interface=fe80::1%2",
        "karyos:udp?endpoint=10.0.0.5:1|interface=[::1]",
        "karyos:udp?endpoint=10.0.0.5:1|paths=eth1@10.0.0.5:1",
        "karyos:udp?destinations=10.0.0.5:1;;10.0.0.6:1",
    ] {
        assert!(
            matches!(refused(uri), ChannelError::InvalidValue { .. }),
            "{uri}"
        );
    }
}

/// One receiver or interface in two spellings is a repetition: an
/// IPv4-mapped IPv6 address is the IPv4 address it maps. Different zones
/// are different addresses.
#[test]
fn a_list_element_in_two_spellings_repeats() {
    for (uri, key) in [
        (
            "karyos:udp?destinations=10.0.0.5:1;[::ffff:10.0.0.5]:1",
            "destinations",
        ),
        (
            "karyos:udp?destinations=[::ffff:10.0.0.5]:1;10.0.0.5:1",
            "destinations",
        ),
        (
            "karyos:udp?endpoint=10.0.0.5:1|paths=10.0.0.7;::ffff:10.0.0.7",
            "paths",
        ),
    ] {
        assert_eq!(
            refused(uri),
            ChannelError::InvalidValue {
                key,
                reason: if key == "paths" {
                    "a path repeats"
                } else {
                    "a destination repeats"
                },
            },
            "{uri}"
        );
    }
    assert_eq!(
        udp("karyos:udp?destinations=[fe80::1%1]:1;[fe80::1%2]:1").destination,
        Destination::MultiDestination {
            destinations: vec![addr("[fe80::1%1]:1"), addr("[fe80::1%2]:1")],
            control: None,
            mode: ControlMode::Manual,
        }
    );
    assert_eq!(
        udp("karyos:udp?destinations=10.0.0.5:1;10.0.0.5:2").destination,
        Destination::MultiDestination {
            destinations: vec![addr("10.0.0.5:1"), addr("10.0.0.5:2")],
            control: None,
            mode: ControlMode::Manual,
        }
    );
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

/// `retransmit-window` (owner item 63): a positive multiple of 32, at most
/// half of a `term-length` the URI gives; `None` when absent, so the
/// driver's setting (half a term by default) stays.
#[test]
fn the_retransmit_window_key_is_validated() {
    assert_eq!(
        udp("karyos:udp?endpoint=10.0.0.5:1").retransmit_window,
        None
    );
    assert_eq!(
        udp("karyos:udp?endpoint=10.0.0.5:1|term-length=65536|retransmit-window=32768")
            .retransmit_window,
        Some(32768)
    );
    for refused in [
        "karyos:udp?endpoint=10.0.0.5:1|retransmit-window=0",
        "karyos:udp?endpoint=10.0.0.5:1|retransmit-window=33",
        "karyos:udp?endpoint=10.0.0.5:1|retransmit-window=+64",
        "karyos:udp?endpoint=10.0.0.5:1|retransmit-window=064",
        "karyos:udp?endpoint=10.0.0.5:1|retransmit-window=4294967328",
        "karyos:udp?endpoint=10.0.0.5:1|term-length=65536|retransmit-window=32800",
    ] {
        assert!(
            matches!(
                ChannelConfig::parse(refused),
                Err(ChannelError::InvalidValue {
                    key: "retransmit-window",
                    ..
                })
            ),
            "{refused}"
        );
    }
    assert_eq!(
        ChannelConfig::parse("karyos:udp?endpoint=10.0.0.5:1|reliable=false|retransmit-window=64"),
        Err(ChannelError::Conflict {
            first: "reliable",
            second: "retransmit-window"
        })
    );
    assert_eq!(
        ChannelConfig::parse("karyos:ipc?retransmit-window=64"),
        Err(ChannelError::NotApplicable {
            key: "retransmit-window"
        })
    );
    assert_eq!(
        ChannelConfig::parse(
            "karyos:udp?endpoint=10.0.0.5:1|retransmit-window=64|retransmit-window=128"
        ),
        Err(ChannelError::Repeated {
            key: "retransmit-window"
        })
    );
}
