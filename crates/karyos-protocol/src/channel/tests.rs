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

/// `trusted` and `encrypted` parse; `authenticated` is still refused.
#[test]
fn trusted_and_encrypted_parse_and_authenticated_is_refused() {
    assert_eq!(
        udp("karyos:udp?endpoint=10.0.0.5:1|security=trusted").security,
        Security::Trusted
    );
    assert_eq!(
        refused("karyos:udp?endpoint=10.0.0.5:1|security=authenticated"),
        ChannelError::SecurityUnsupported {
            class: "authenticated"
        }
    );
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
            Key::RequireAbortAck => assert_eq!(
                refused("karyos:udp?endpoint=10.0.0.5:1|require-abort-ack=true"),
                ChannelError::SecurityUnsupported {
                    class: "authenticated"
                }
            ),
            Key::NakControl => assert_eq!(
                udp("karyos:udp?group=239.1.1.1:4000|nak-control=239.1.1.2:4001").nak_control,
                vec![addr("239.1.1.2:4001")]
            ),
            Key::Linger => assert_eq!(
                udp("karyos:udp?endpoint=10.0.0.5:1|linger=250ms").linger,
                Some(Duration::from_millis(250))
            ),
            Key::PathSkew => assert_eq!(
                udp("karyos:udp?endpoint=10.0.0.5:1|path-skew=250us").path_skew,
                Some(Duration::from_micros(250))
            ),
            Key::EtfPriority | Key::EtfDelta => assert_eq!(
                udp("karyos:udp?endpoint=10.0.0.5:1|interface=10.0.0.1|etf-priority=3|etf-delta=100us")
                    .etf,
                Some(EtfDeclaration {
                    priority: 3,
                    delta: Duration::from_micros(100),
                })
            ),
            Key::ChannelKeyId
            | Key::PairwiseKeyId
            | Key::ReceiverId
            | Key::ChannelId
            | Key::PublisherId => assert_eq!(
                udp("karyos:udp?endpoint=10.0.0.5:1|mtu=1408|security=encrypted|channel-key=3|pairwise-key=9|receiver-id=77|channel-id=7|publisher-id=5")
                    .security,
                Security::Encrypted(EncryptedChannel {
                    channel_key_id: 3,
                    pairwise_key_id: 9,
                    receiver_id: 77,
                    channel_id: 7,
                    publisher_id: 5,
                })
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
        "karyos:udp?endpoint=010.0.0.5:1",
        "karyos:udp?endpoint=10.0.0.5:1|interface=fe80::1%2",
        "karyos:udp?endpoint=10.0.0.5:1|interface=[::1]",
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

/// `require-abort-ack` is defined and refused while the authenticated
/// capability is unsupported, never downgraded (owner decision item 8, #648).
#[test]
fn require_abort_ack_is_refused_until_authenticated_is_supported() {
    assert_eq!(
        refused("karyos:udp?endpoint=10.0.0.5:1|require-abort-ack=true"),
        ChannelError::SecurityUnsupported {
            class: "authenticated"
        }
    );
    assert_eq!(
        refused("karyos:udp?endpoint=10.0.0.5:1|security=trusted|require-abort-ack=true"),
        ChannelError::SecurityUnsupported {
            class: "authenticated"
        }
    );
    assert_eq!(
        udp("karyos:udp?endpoint=10.0.0.5:1|require-abort-ack=false"),
        udp("karyos:udp?endpoint=10.0.0.5:1")
    );
    assert!(matches!(
        refused("karyos:udp?endpoint=10.0.0.5:1|require-abort-ack=yes"),
        ChannelError::InvalidValue {
            key: "require-abort-ack",
            ..
        }
    ));
    assert!(matches!(
        refused("karyos:ipc?require-abort-ack=true"),
        ChannelError::NotApplicable {
            key: "require-abort-ack"
        }
    ));
    assert!(matches!(
        refused("karyos:udp?endpoint=10.0.0.5:1|require-abort-ack=true|require-abort-ack=true"),
        ChannelError::Repeated {
            key: "require-abort-ack"
        }
    ));
}

/// karyos#635 (owner item 11): paired unicast paths, `interface@endpoint`
/// per element, are their own destination form, with the grammar of
/// CHANNEL-URI.md section 6.
#[test]
fn paired_paths_follow_their_grammar() {
    let channel = udp("karyos:udp?paths=eth1@10.0.0.5:40123;eth2@10.1.0.5:40123");
    assert_eq!(
        channel.paths,
        vec![
            Interface::Name("eth1".to_owned()),
            Interface::Name("eth2".to_owned())
        ]
    );
    assert_eq!(
        channel.destination,
        Destination::PairedPaths {
            endpoints: vec![addr("10.0.0.5:40123"), addr("10.1.0.5:40123")]
        }
    );
    // IPv6, with a numeric scope id, and an address as the interface.
    let channel = udp("karyos:udp?paths=fe80::2@[fe80::1%2]:40123;eth2@[fd00::5]:40123");
    assert_eq!(
        channel.paths[0],
        Interface::Address("fe80::2".parse().unwrap())
    );
    assert_eq!(
        channel.destination,
        Destination::PairedPaths {
            endpoints: vec![addr("[fe80::1%2]:40123"), addr("[fd00::5]:40123")]
        }
    );
    // One pair is a path count inside the bound.
    assert!(matches!(
        udp("karyos:udp?paths=eth1@10.0.0.5:1").destination,
        Destination::PairedPaths { .. }
    ));
    for (uri, reason) in [
        (
            "karyos:udp?paths=eth1@10.0.0.5:1;eth1@10.0.0.6:1",
            "a path repeats",
        ),
        (
            "karyos:udp?paths=eth1@10.0.0.5:1;eth2@10.0.0.5:1",
            "an endpoint repeats",
        ),
        (
            "karyos:udp?paths=eth1@10.0.0.5:1;eth2@[::ffff:10.0.0.5]:1",
            "an endpoint repeats",
        ),
        (
            "karyos:udp?paths=eth1@10.0.0.5:1;eth2@[fd00::5]:1",
            "endpoints of two address families",
        ),
        (
            "karyos:udp?paths=eth1@10.0.0.5:1;eth2@10.0.0.6:1;eth3@10.0.0.7:1;eth4@10.0.0.8:1;eth5@10.0.0.9:1",
            "more than 4 paths",
        ),
        (
            "karyos:udp?paths=eth1@10.0.0.5:1;eth2",
            "paired and unpaired paths",
        ),
        ("karyos:udp?paths=eth1@239.1.1.1:1", "a multicast address"),
        ("karyos:udp?paths=eth1@10.0.0.5:0", "port 0"),
        ("karyos:udp?paths=eth1@0.0.0.0:1", "unspecified address"),
        ("karyos:udp?paths=eth1@10.0.0.5", "not an address and port"),
        (
            "karyos:udp?paths=eth1@[fe80::1%eth0]:1",
            "not an address and port",
        ),
        (
            "karyos:udp?paths=eth/1@10.0.0.5:1",
            "not an address or an interface name",
        ),
    ] {
        assert_eq!(
            refused(uri),
            ChannelError::InvalidValue {
                key: "paths",
                reason
            },
            "{uri}"
        );
    }
    // No other destination key goes with paired paths, in either order.
    for (uri, other) in [
        (
            "karyos:udp?paths=eth1@10.0.0.5:1|destinations=10.0.0.6:1",
            "destinations",
        ),
        (
            "karyos:udp?destinations=10.0.0.6:1|paths=eth1@10.0.0.5:1",
            "destinations",
        ),
        (
            "karyos:udp?endpoint=10.0.0.6:1|paths=eth1@10.0.0.5:1",
            "endpoint",
        ),
        (
            "karyos:udp?paths=eth1@10.0.0.5:1|group=239.1.1.1:1",
            "group",
        ),
        (
            "karyos:udp?control=10.0.0.6:1|paths=eth1@10.0.0.5:1",
            "control",
        ),
    ] {
        assert_eq!(
            refused(uri),
            ChannelError::Conflict {
                first: "paths",
                second: other
            },
            "{uri}"
        );
    }
    // Nor does `destinations` with unpaired paths, in either order.
    for uri in [
        "karyos:udp?paths=10.0.0.1;10.0.0.2|destinations=10.0.0.6:1",
        "karyos:udp?destinations=10.0.0.6:1|paths=10.0.0.1;10.0.0.2",
    ] {
        assert_eq!(
            refused(uri),
            ChannelError::Conflict {
                first: "paths",
                second: "destinations"
            },
            "{uri}"
        );
    }
    // `interface` still conflicts with `paths`; `ttl` and `fc` do not apply.
    assert_eq!(
        refused("karyos:udp?paths=eth1@10.0.0.5:1|interface=10.0.0.1"),
        ChannelError::Conflict {
            first: "interface",
            second: "paths"
        }
    );
    for (uri, key) in [
        ("karyos:udp?paths=eth1@10.0.0.5:1|ttl=1", "ttl"),
        ("karyos:udp?paths=eth1@10.0.0.5:1|fc=min", "fc"),
    ] {
        assert_eq!(refused(uri), ChannelError::NotApplicable { key }, "{uri}");
    }
}

/// karyos#652 (owner item 16): `linger` is a duration of the URI grammar,
/// 0 to 60 s, on a udp channel only; absent, the driver's setting stays.
#[test]
fn linger_is_a_bounded_duration() {
    assert_eq!(udp("karyos:udp?endpoint=10.0.0.5:1").linger, None);
    for (text, expected) in [
        ("0s", Duration::ZERO),
        ("0ns", Duration::ZERO),
        ("250ms", Duration::from_millis(250)),
        ("5s", Duration::from_secs(5)),
        ("60s", Duration::from_secs(60)),
        ("60000000us", Duration::from_secs(60)),
    ] {
        assert_eq!(
            udp(&format!("karyos:udp?endpoint=10.0.0.5:1|linger={text}")).linger,
            Some(expected),
            "{text}"
        );
    }
    for text in ["61s", "60000000001ns"] {
        assert_eq!(
            refused(&format!("karyos:udp?endpoint=10.0.0.5:1|linger={text}")),
            ChannelError::InvalidValue {
                key: "linger",
                reason: "above 60 s"
            },
            "{text}"
        );
    }
    for (text, error) in [
        ("5", DurationError::MissingUnit),
        ("5m", DurationError::UnknownUnit),
        ("05s", DurationError::NotDecimal),
    ] {
        assert_eq!(
            refused(&format!("karyos:udp?endpoint=10.0.0.5:1|linger={text}")),
            ChannelError::InvalidDuration {
                key: "linger",
                error
            },
            "{text}"
        );
    }
    assert_eq!(
        refused("karyos:ipc?linger=1s"),
        ChannelError::NotApplicable { key: "linger" }
    );
    assert_eq!(
        refused("karyos:udp?endpoint=10.0.0.5:1|linger=1s|linger=2s"),
        ChannelError::Repeated { key: "linger" }
    );
}

/// karyos#656 (owner decision item 26): port 0 is admitted for `endpoint`
/// alone, the ephemeral port of a unicast subscription; a publication
/// refuses it, and so does every other address key, at parse time.
#[test]
fn port_zero_is_an_endpoint_role_only() {
    for uri in [
        "karyos:udp?endpoint=10.0.0.5:0",
        "karyos:udp?endpoint=[::1]:0",
    ] {
        let channel = ChannelConfig::parse(uri).unwrap();
        let Media::Udp(udp) = &channel.media else {
            panic!("not udp: {uri}");
        };
        assert!(
            matches!(udp.destination, Destination::Unicast(address) if address.port() == 0),
            "{uri}"
        );
        assert!(
            matches!(
                channel.check_publication(),
                Err(ChannelError::InvalidValue {
                    key: "endpoint",
                    ..
                })
            ),
            "{uri}"
        );
    }
    // A named port is a publication's as before.
    ChannelConfig::parse("karyos:udp?endpoint=10.0.0.5:1")
        .unwrap()
        .check_publication()
        .unwrap();
    // The other address rules still hold on port 0.
    for uri in [
        "karyos:udp?endpoint=0.0.0.0:0",
        "karyos:udp?endpoint=239.1.1.1:0",
    ] {
        assert!(
            matches!(
                refused(uri),
                ChannelError::InvalidValue {
                    key: "endpoint",
                    ..
                }
            ),
            "{uri}"
        );
    }
    // Groups, destinations and control keep refusing port 0.
    for (uri, key) in [
        ("karyos:udp?group=239.1.1.1:0", "group"),
        ("karyos:udp?destinations=10.0.0.5:0", "destinations"),
        (
            "karyos:udp?destinations=10.0.0.5:1;10.0.0.6:0",
            "destinations",
        ),
        ("karyos:udp?control=10.0.0.5:0", "control"),
    ] {
        assert!(
            matches!(refused(uri), ChannelError::InvalidValue { key: found, .. } if found == key),
            "{uri}"
        );
    }
    // Each path binds its own socket, so port 0 with paths is refused.
    assert_eq!(
        refused("karyos:udp?endpoint=10.0.0.5:0|paths=10.0.0.1;10.0.0.2"),
        ChannelError::Conflict {
            first: "endpoint",
            second: "paths"
        }
    );
}

/// karyos#654 (owner item 8): `nak-control` names one multicast control
/// group per path, in the order of `paths`, on a multicast channel only.
#[test]
fn nak_control_maps_each_path() {
    let at = |text: &str| text.parse::<SocketAddr>().unwrap();
    assert!(
        udp("karyos:udp?group=239.1.1.1:4000")
            .nak_control
            .is_empty()
    );
    assert_eq!(
        udp("karyos:udp?group=239.1.1.1:4000|nak-control=239.1.1.2:4001").nak_control,
        vec![at("239.1.1.2:4001")]
    );
    assert_eq!(
        udp("karyos:udp?group=239.1.1.1:4000|paths=10.0.0.1;10.0.0.2|nak-control=239.1.1.2:4001;239.1.1.3:4001")
            .nak_control,
        vec![at("239.1.1.2:4001"), at("239.1.1.3:4001")]
    );
    for (uri, reason) in [
        // Ambiguous: not one group per path.
        (
            "karyos:udp?group=239.1.1.1:4000|paths=10.0.0.1;10.0.0.2|nak-control=239.1.1.2:4001",
            "not one control group per path",
        ),
        (
            "karyos:udp?group=239.1.1.1:4000|nak-control=239.1.1.2:4001;239.1.1.3:4001",
            "not one control group per path",
        ),
        (
            "karyos:udp?group=239.1.1.1:4000|paths=10.0.0.1;10.0.0.2|nak-control=239.1.1.2:4001;239.1.1.2:4001",
            "a control group repeats",
        ),
        (
            "karyos:udp?group=239.1.1.1:4000|nak-control=10.0.0.2:4001",
            "not a multicast address",
        ),
        (
            "karyos:udp?group=239.1.1.1:4000|nak-control=[ff02::1]:4001",
            "not the group's address family",
        ),
        (
            "karyos:udp?group=239.1.1.1:4000|nak-control=239.1.1.1:4000",
            "the data group itself",
        ),
        (
            "karyos:udp?group=239.1.1.1:4000|nak-control=239.1.1.2:0",
            "port 0",
        ),
    ] {
        assert_eq!(
            refused(uri),
            ChannelError::InvalidValue {
                key: "nak-control",
                reason
            },
            "{uri}"
        );
    }
    for uri in [
        "karyos:udp?endpoint=10.0.0.5:1|nak-control=239.1.1.2:4001",
        "karyos:udp?destinations=10.0.0.5:1|nak-control=239.1.1.2:4001",
    ] {
        assert_eq!(
            refused(uri),
            ChannelError::NotApplicable { key: "nak-control" },
            "{uri}"
        );
    }
    assert_eq!(
        refused("karyos:ipc?nak-control=239.1.1.2:4001"),
        ChannelError::NotApplicable { key: "nak-control" }
    );
}

/// karyos#1056 (owner item 17): `path-skew` is a duration of the URI
/// grammar, 0 to 1 s, on a udp channel only; absent, the driver's settings
/// stay.
#[test]
fn path_skew_is_a_bounded_duration() {
    assert_eq!(udp("karyos:udp?endpoint=10.0.0.5:1").path_skew, None);
    for (text, expected) in [
        ("0ns", Duration::ZERO),
        ("1ms", Duration::from_millis(1)),
        ("1s", Duration::from_secs(1)),
        ("1000000us", Duration::from_secs(1)),
    ] {
        assert_eq!(
            udp(&format!(
                "karyos:udp?group=239.1.1.1:1|paths=eth1;eth2|path-skew={text}"
            ))
            .path_skew,
            Some(expected),
            "{text}"
        );
    }
    for text in ["2s", "1000000001ns"] {
        assert_eq!(
            refused(&format!("karyos:udp?endpoint=10.0.0.5:1|path-skew={text}")),
            ChannelError::InvalidValue {
                key: "path-skew",
                reason: "above 1 s"
            },
            "{text}"
        );
    }
    for (text, error) in [
        ("1", DurationError::MissingUnit),
        ("1h", DurationError::UnknownUnit),
        ("01ms", DurationError::NotDecimal),
    ] {
        assert_eq!(
            refused(&format!("karyos:udp?endpoint=10.0.0.5:1|path-skew={text}")),
            ChannelError::InvalidDuration {
                key: "path-skew",
                error
            },
            "{text}"
        );
    }
    assert_eq!(
        refused("karyos:ipc?path-skew=1ms"),
        ChannelError::NotApplicable { key: "path-skew" }
    );
}

const ENC_KEYS: &str = "channel-key=3|pairwise-key=4|receiver-id=42|channel-id=7|publisher-id=5";

/// ADR-0114 sections 6 and 11: an `encrypted` channel above `mtu` 1408 is
/// refused at parse for its MTU, before anything else; at or below it the
/// channel parses with its keys and receiver.
#[test]
fn an_encrypted_channel_takes_mtu_at_most_1408() {
    for mtu in [1409, 1500, 8192] {
        assert!(matches!(
            refused(&format!(
                "karyos:udp?endpoint=10.0.0.5:1|security=encrypted|mtu={mtu}|{ENC_KEYS}"
            )),
            ChannelError::InvalidValue { key: "mtu", .. }
        ));
        // Refused for the MTU even without its keys.
        assert!(matches!(
            refused(&format!(
                "karyos:udp?endpoint=10.0.0.5:1|security=encrypted|mtu={mtu}"
            )),
            ChannelError::InvalidValue { key: "mtu", .. }
        ));
    }
    for mtu in [256, 1408] {
        let config = udp(&format!(
            "karyos:udp?endpoint=10.0.0.5:1|security=encrypted|mtu={mtu}|{ENC_KEYS}"
        ));
        assert_eq!(
            config.security,
            Security::Encrypted(EncryptedChannel {
                channel_key_id: 3,
                pairwise_key_id: 4,
                receiver_id: 42,
                channel_id: 7,
                publisher_id: 5,
            })
        );
    }
    // The same MTU is valid on a trusted channel.
    assert!(
        ChannelConfig::parse("karyos:udp?endpoint=10.0.0.5:1|security=trusted|mtu=8192").is_ok()
    );
    assert_eq!(MAX_ENCRYPTED_MTU, 1408);
}

/// ADR-0109 (#625): `etf-priority` and `etf-delta` go together, on a
/// unicast `endpoint` with an `interface` address; the delta is positive
/// and below 2^32 ns; a channel without them has no declaration.
#[test]
fn the_etf_declaration_is_checked() {
    assert_eq!(udp("karyos:udp?endpoint=10.0.0.5:1").etf, None);
    let base = "karyos:udp?endpoint=10.0.0.5:1|interface=10.0.0.1";
    for (rest, key) in [
        ("|etf-priority=3", "etf-priority"),
        ("|etf-delta=1us", "etf-delta"),
        ("|etf-priority=-1|etf-delta=1us", "etf-priority"),
        ("|etf-priority=03|etf-delta=1us", "etf-priority"),
        ("|etf-priority=4294967296|etf-delta=1us", "etf-priority"),
        ("|etf-priority=3|etf-delta=0ns", "etf-delta"),
        ("|etf-priority=3|etf-delta=5s", "etf-delta"),
    ] {
        assert!(
            matches!(
                refused(&format!("{base}{rest}")),
                ChannelError::InvalidValue { key: k, .. } if k == key
            ),
            "{rest}"
        );
    }
    assert!(matches!(
        refused("karyos:udp?endpoint=10.0.0.5:1|etf-priority=3|etf-delta=1us"),
        ChannelError::InvalidValue {
            key: "etf-priority",
            ..
        }
    ));
    assert!(matches!(
        refused(&format!("{base}|etf-priority=3|etf-delta=1")),
        ChannelError::InvalidDuration {
            key: "etf-delta",
            ..
        }
    ));
    assert_eq!(
        refused("karyos:udp?group=239.1.1.1:4000|interface=10.0.0.1|etf-priority=3|etf-delta=1us"),
        ChannelError::NotApplicable {
            key: "etf-priority"
        }
    );
    assert_eq!(
        udp(&format!(
            "{base}|etf-priority=4294967295|etf-delta=4294967295ns"
        ))
        .etf,
        Some(EtfDeclaration {
            priority: u32::MAX,
            delta: Duration::from_nanos(u64::from(u32::MAX)),
        })
    );
}

/// ADR-0114 section 4a and the v1 scope: an `encrypted` channel requires
/// each of its three key settings, nonzero and in range; serves one unicast
/// `endpoint` only (multicast, `destinations`, `control` and `paths` are
/// refused, never downgraded); and the key settings belong to it alone.
#[test]
fn an_encrypted_channel_needs_its_keys_and_one_unicast_receiver() {
    let base = "karyos:udp?endpoint=10.0.0.5:1|security=encrypted";
    for missing in [
        "channel-key",
        "pairwise-key",
        "receiver-id",
        "channel-id",
        "publisher-id",
    ] {
        let keys: Vec<&str> = ENC_KEYS
            .split('|')
            .filter(|kv| !kv.starts_with(missing))
            .collect();
        assert_eq!(
            refused(&format!("{base}|{}", keys.join("|"))),
            ChannelError::InvalidValue {
                key: KEYS.iter().find(|(name, _)| *name == missing).unwrap().0,
                reason: "required on an `encrypted` channel"
            },
            "{missing}"
        );
    }
    for bad in [
        "channel-key=0|pairwise-key=4|receiver-id=42",
        "channel-key=4294967296|pairwise-key=4|receiver-id=42",
        "channel-key=3|pairwise-key=04|receiver-id=42",
        "channel-key=3|pairwise-key=4|receiver-id=0",
        "channel-key=3|pairwise-key=4|receiver-id=18446744073709551616",
        "channel-key=3|pairwise-key=4|receiver-id=42|channel-id=0|publisher-id=5",
        "channel-key=3|pairwise-key=4|receiver-id=42|channel-id=7|publisher-id=0",
        "channel-key=3|pairwise-key=4|receiver-id=42|channel-id=07|publisher-id=5",
        "channel-key=3|pairwise-key=4|receiver-id=42|channel-id=7|publisher-id=18446744073709551616",
    ] {
        assert!(
            matches!(
                refused(&format!("{base}|{bad}")),
                ChannelError::InvalidValue { .. }
            ),
            "{bad}"
        );
    }
    assert_eq!(
        udp(&format!(
            "{base}|channel-key=4294967295|pairwise-key=1|receiver-id=18446744073709551615|channel-id=18446744073709551615|publisher-id=1"
        ))
        .security,
        Security::Encrypted(EncryptedChannel {
            channel_key_id: u32::MAX,
            pairwise_key_id: 1,
            receiver_id: u64::MAX,
            channel_id: u64::MAX,
            publisher_id: 1,
        })
    );
    for other in [
        "group=239.1.1.1:4000",
        "destinations=10.0.0.5:1;10.0.0.6:1",
        "control=10.0.0.5:1|control-mode=dynamic",
        "endpoint=10.0.0.5:1|paths=10.0.0.1;10.0.0.2",
        "paths=10.0.0.1@10.0.0.5:1;10.0.0.2@10.0.0.6:1",
    ] {
        assert_eq!(
            refused(&format!("karyos:udp?{other}|security=encrypted|{ENC_KEYS}")),
            ChannelError::InvalidValue {
                key: "security",
                reason: "`encrypted` on a channel other than one unicast `endpoint`"
            },
            "{other}"
        );
    }
    for key in [
        "channel-key=3",
        "pairwise-key=4",
        "receiver-id=42",
        "channel-id=7",
        "publisher-id=5",
    ] {
        let name = key.split('=').next().unwrap();
        for class in ["", "|security=trusted"] {
            assert_eq!(
                refused(&format!("karyos:udp?endpoint=10.0.0.5:1{class}|{key}")),
                ChannelError::NotApplicable {
                    key: KEYS.iter().find(|(known, _)| *known == name).unwrap().0
                },
                "{key}{class}"
            );
        }
        assert_eq!(
            refused(&format!("karyos:ipc?{key}")),
            ChannelError::NotApplicable {
                key: KEYS.iter().find(|(known, _)| *known == name).unwrap().0
            }
        );
    }
}
