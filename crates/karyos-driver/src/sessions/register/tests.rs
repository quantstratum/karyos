// SPDX-License-Identifier: Apache-2.0

//! The bounds of dynamic registration as limits (design 3.2, 9.2; SPEC.md
//! §6): each step's refusal, the rates and pending bounds at their exact
//! edge, the one-ERR-per-interval rule and the reflection bound.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use karyos_protocol::network::{ControlKind, Receiver, RspRegister};

use super::*;

const SECOND: u64 = 1_000_000_000;
/// A start time far from zero, so ages never saturate.
const T0: u64 = 1_000 * SECOND;

fn range(network: [u8; 4], prefix: u8) -> AddressRange {
    AddressRange::new(IpAddr::from(network), prefix).unwrap()
}

/// The policy of an IPv4 publication admitting `ranges`.
fn allow(ranges: &[AddressRange]) -> RegistrationPolicy {
    RegistrationPolicy::new(RegistrationAllowlist::new(ranges).unwrap(), true)
}

/// One publication's allowlist with the driver's limits.
struct Setup {
    allow: RegistrationPolicy,
    config: RegistrationConfig,
}

fn config(ranges: &[AddressRange]) -> Setup {
    Setup {
        allow: allow(ranges),
        config: RegistrationConfig::default(),
    }
}

/// The driver's registrations and one publication's allowlist.
struct Harness {
    registrations: Registrations,
    allow: RegistrationPolicy,
}

impl Harness {
    fn register(
        &mut self,
        source: SocketAddr,
        register: &RspRegister,
        capacity: Capacity,
        now: u64,
    ) -> RegisterOutcome {
        self.registrations.register(
            &mut self.allow,
            source,
            register,
            (Existing::None, capacity),
            now,
        )
    }

    fn challenged(
        &mut self,
        source: SocketAddr,
        boot: [u64; 2],
        now: u64,
    ) -> Option<PendingRegistration> {
        self.registrations
            .challenged(&mut self.allow, STREAM, source, boot, now)
    }

    fn pending(&self) -> &[PendingRegistration] {
        self.registrations.pending()
    }

    fn counters(&self) -> RegistrationCounters {
        self.registrations.counters()
    }
}

fn registrations(setup: Setup) -> Harness {
    Harness {
        registrations: Registrations::new(setup.config, T0).unwrap(),
        allow: setup.allow,
    }
}

fn lan() -> Harness {
    registrations(config(&[range([10, 0, 0, 0], 8)]))
}

const STREAM: i32 = 1001;

fn source(last: u8, port: u16) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, last], port))
}

fn register(receiver_id: u64) -> RspRegister {
    RspRegister {
        stream_id: STREAM,
        receiver: Receiver {
            receiver_boot_id: [receiver_id, 1],
            receiver_id,
        },
    }
}

/// The bytes `outcome` sends: one ANNOUNCE (72) or one ERR (40).
fn sent_bytes(outcome: RegisterOutcome) -> usize {
    match outcome {
        RegisterOutcome::Announce { .. } => ControlKind::SetupAnnounce.length(1).unwrap(),
        RegisterOutcome::Refuse { .. } => ControlKind::Registration.length(0).unwrap(),
        RegisterOutcome::Drop(_) => 0,
    }
}

#[test]
fn a_missing_allowlist_is_a_refusal_never_a_permissive_default() {
    assert_eq!(
        RegistrationAllowlist::new(&[]),
        Err(RegistrationConfigError::EmptyAllowlist)
    );
    let too_many = vec![range([10, 0, 0, 0], 8); MAX_ALLOW_RANGES + 1];
    assert_eq!(
        RegistrationAllowlist::new(&too_many),
        Err(RegistrationConfigError::TooManyRanges {
            count: MAX_ALLOW_RANGES + 1
        })
    );
    assert!(RegistrationAllowlist::new(&too_many[..MAX_ALLOW_RANGES]).is_ok());
}

#[test]
fn ranges_are_named_exactly() {
    // Host bits below the prefix, or a prefix longer than the address.
    assert_eq!(
        AddressRange::new(IpAddr::from([10, 0, 0, 1]), 8),
        Err(RegistrationConfigError::InvalidRange {
            network: IpAddr::from([10, 0, 0, 1]),
            prefix: 8
        })
    );
    assert_eq!(
        AddressRange::new(IpAddr::from([10, 0, 0, 0]), 33),
        Err(RegistrationConfigError::InvalidRange {
            network: IpAddr::from([10, 0, 0, 0]),
            prefix: 33
        })
    );
    assert_eq!(
        AddressRange::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 129),
        Err(RegistrationConfigError::InvalidRange {
            network: IpAddr::V6(Ipv6Addr::LOCALHOST),
            prefix: 129
        })
    );
    let lan = range([10, 1, 0, 0], 16);
    assert!(lan.contains(IpAddr::from([10, 1, 255, 7])));
    assert!(!lan.contains(IpAddr::from([10, 2, 0, 1])));
    // An IPv4-mapped IPv6 address is its IPv4 address.
    let mapped = IpAddr::V6(Ipv4Addr::new(10, 1, 0, 9).to_ipv6_mapped());
    assert!(lan.contains(mapped));
    // A /32 is one host; a /0 is every address of its family only.
    let host = range([10, 1, 2, 3], 32);
    assert!(host.contains(IpAddr::from([10, 1, 2, 3])));
    assert!(!host.contains(IpAddr::from([10, 1, 2, 4])));
    let any_v4 = range([0, 0, 0, 0], 0);
    assert!(any_v4.contains(IpAddr::from([203, 0, 113, 1])));
    assert!(!any_v4.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

/// One change to a valid configuration.
type Change = fn(&mut RegistrationConfig);

#[test]
fn limits_are_mandatory_nonzero_bounded_and_named() {
    let base = RegistrationConfig::default();
    assert_eq!(base.validate(), Ok(()));
    let cases: [(Change, &str); 11] = [
        (|c| c.rate = 0, "rate"),
        (|c| c.sources = 0, "sources"),
        (|c| c.sources = MAX_REGISTRATION_TABLE + 1, "sources"),
        (|c| c.pending = 0, "pending"),
        (|c| c.pending = MAX_REGISTRATION_TABLE + 1, "pending"),
        (|c| c.pending = usize::MAX, "pending"),
        (|c| c.pending_per_source = 0, "pending_per_source"),
        (
            |c| c.pending_per_source = c.pending + 1,
            "pending_per_source",
        ),
        (|c| c.refusal_interval = 0, "refusal_interval"),
        (|c| c.join_timeout = 0, "join_timeout"),
        (|c| c.move_quiet = 0, "move_quiet"),
    ];
    for (change, field) in cases {
        let mut bad = base;
        change(&mut bad);
        let refused = Registrations::new(bad, T0).map(|_| ());
        assert_eq!(
            refused,
            Err(RegistrationConfigError::InvalidLimit { field })
        );
        assert!(refused.unwrap_err().to_string().contains(field));
    }
    // The ceiling itself is accepted and allocated.
    let mut top = base;
    top.sources = MAX_REGISTRATION_TABLE;
    top.pending = MAX_REGISTRATION_TABLE;
    assert!(Registrations::new(top, T0).is_ok());
}

/// Design 3.2 steps 3 and 5 scope the rate and the pending table to the
/// driver: two dynamic publications share them, each with its own
/// allowlist.
#[test]
fn the_driver_limits_are_shared_by_its_publications() {
    let c = RegistrationConfig {
        pending: 3,
        rate: 4,
        ..RegistrationConfig::default()
    };
    let mut driver = Registrations::new(c, T0).unwrap();
    let mut lan = allow(&[range([10, 0, 0, 0], 8)]);
    let mut other = allow(&[range([10, 9, 0, 0], 16)]);
    let mut on = |allowlist: &mut RegistrationPolicy, from: SocketAddr, stream_id: i32| {
        let mut r = register(u64::from(from.port()));
        r.stream_id = stream_id;
        driver.register(allowlist, from, &r, (Existing::None, Capacity::Free), T0)
    };
    for (host, stream) in [(1, 1), (2, 2), (3, 1)] {
        let from = SocketAddr::from(([10, 9, 0, host], 40_000));
        let allowlist = if stream == 1 { &mut lan } else { &mut other };
        assert!(matches!(
            on(allowlist, from, stream),
            RegisterOutcome::Announce { .. }
        ));
    }
    // The fourth, to either publication, finds the driver's table full
    // and replaces its oldest entry, the first publication's.
    let from = SocketAddr::from(([10, 9, 0, 4], 40_000));
    assert_eq!(
        on(&mut other, from, 2),
        RegisterOutcome::Announce { source: from }
    );
    // Then the driver's total of four per second is spent for both.
    assert_eq!(
        on(&mut lan, SocketAddr::from(([10, 9, 0, 5], 40_000)), 1),
        RegisterOutcome::Drop(RegisterDrop::Rate)
    );
    assert_eq!(driver.counters().pending_replaced, 1);
    assert_eq!(driver.pending().len(), 3);
    assert_eq!(driver.pending()[0].source.ip(), IpAddr::from([10, 9, 0, 2]));
    // A CHALLENGE takes only the entry of its own stream.
    let from = SocketAddr::from(([10, 9, 0, 2], 40_000));
    assert_eq!(driver.challenged(&mut lan, 1, from, [40_000, 1], T0), None);
    assert!(
        driver
            .challenged(&mut other, 2, from, [40_000, 1], T0)
            .is_some()
    );
}

#[test]
fn counters_are_checked_and_sticky_on_overflow() {
    let mut counters = RegistrationCounters {
        registered: u64::MAX,
        ..RegistrationCounters::default()
    };
    counters.bump(|c| &mut c.registered);
    assert_eq!(counters.registered, u64::MAX);
    assert!(counters.overflowed);
    counters.bump(|c| &mut c.retried);
    assert_eq!(counters.retried, 1);
    assert!(counters.overflowed);
}

#[test]
fn a_registration_inside_the_allowlist_gets_one_announce_and_a_pending_entry() {
    let mut r = lan();
    let from = source(5, 40_123);
    let outcome = r.register(from, &register(7), Capacity::Free, T0);
    assert_eq!(outcome, RegisterOutcome::Announce { source: from });
    assert_eq!(r.pending().len(), 1);
    assert_eq!(r.pending()[0].receiver, register(7).receiver);
    assert_eq!(r.pending()[0].expires, T0 + 5 * SECOND);
    assert_eq!(r.counters().registered, 1);
}

#[test]
fn a_source_outside_the_allowlist_causes_nothing() {
    let mut r = lan();
    let outside = SocketAddr::from(([192, 0, 2, 1], 40_123));
    for at in 0..100 {
        assert_eq!(
            r.register(outside, &register(7), Capacity::Free, T0 + at),
            RegisterOutcome::Drop(RegisterDrop::NotAllowed)
        );
    }
    assert!(r.pending().is_empty());
    // Refused before any rate is charged: an allowed source still has its
    // whole budget.
    assert_eq!(r.counters().dropped_not_allowed, 100);
    for at in 0..20 {
        assert!(matches!(
            r.register(source(5, 1), &register(8), Capacity::Free, T0 + at),
            RegisterOutcome::Announce { .. }
        ));
    }
}

#[test]
fn invalid_sources_are_dropped() {
    let mut r = registrations(config(&[range([0, 0, 0, 0], 0)]));
    for bad in [
        SocketAddr::from(([10, 0, 0, 5], 0)),
        SocketAddr::from(([0, 0, 0, 0], 40_123)),
        SocketAddr::from(([224, 0, 0, 1], 40_123)),
        SocketAddr::from(([255, 255, 255, 255], 40_123)),
        // Another family than the endpoint's.
        SocketAddr::from((Ipv6Addr::LOCALHOST, 40_123)),
    ] {
        assert_eq!(
            r.register(bad, &register(7), Capacity::Free, T0),
            RegisterOutcome::Drop(RegisterDrop::Source),
            "{bad}"
        );
    }
    // An IPv4-mapped IPv6 source is its IPv4 source.
    let mapped = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped(), 40_123));
    assert_eq!(
        r.register(mapped, &register(7), Capacity::Free, T0),
        RegisterOutcome::Announce {
            source: source(5, 40_123)
        }
    );
}

/// ADR-0082, decision 1: the allowlist restricts admission and supplies no
/// authentication. A source the broadest allowlist admits is still rate
/// limited, bounded and capacity checked, gets only an unverified pending
/// entry, and is answered on the CHALLENGE path only if it receives at
/// its source with the boot id it registered.
#[test]
fn the_allowlist_is_not_authentication() {
    let any = [range([0, 0, 0, 0], 0)];
    let mut r = registrations(config(&any));
    let from = source(5, 40_123);
    // Admission is not trust: the per-source bounds still apply, a third
    // entry replacing the source's oldest.
    for id in [3, 1, 2] {
        assert!(matches!(
            r.register(from, &register(id), Capacity::Free, T0),
            RegisterOutcome::Announce { .. }
        ));
    }
    assert_eq!(r.counters().pending_replaced, 1);
    // A full table refuses an allowed source as any other.
    let other = source(6, 40_123);
    assert_eq!(
        r.register(other, &register(4), Capacity::Full, T0),
        RegisterOutcome::Refuse { source: other }
    );
    // The entry proves nothing: a CHALLENGE from another source, or with
    // another boot id, does not take it.
    assert_eq!(r.challenged(source(9, 40_123), [1, 1], T0), None);
    assert_eq!(r.challenged(from, [99, 1], T0), None);
    assert_eq!(r.pending().len(), 2);
    let taken = r.challenged(from, [1, 1], T0).unwrap();
    assert_eq!(taken.receiver.receiver_id, 1);
    assert_eq!(r.pending().len(), 1);
    // Taken once: the same CHALLENGE again finds nothing.
    assert_eq!(r.challenged(from, [1, 1], T0), None);
}

#[test]
fn the_per_source_rate_is_a_limit() {
    let mut r = lan();
    let from = source(5, 40_123);
    // The burst is the rate: 20 within one instant, as retries of one
    // entry, then nothing until the bucket refills.
    for _ in 0..20 {
        assert!(matches!(
            r.register(from, &register(7), Capacity::Free, T0),
            RegisterOutcome::Announce { .. }
        ));
    }
    assert_eq!(
        r.register(from, &register(7), Capacity::Free, T0),
        RegisterOutcome::Drop(RegisterDrop::SourceRate)
    );
    assert_eq!(r.counters().retried, 19);
    // Another port of the same address shares its bucket (karyos#940);
    // another address has its own.
    assert_eq!(
        r.register(source(5, 40_124), &register(8), Capacity::Free, T0),
        RegisterOutcome::Drop(RegisterDrop::SourceRate)
    );
    assert!(matches!(
        r.register(source(6, 40_123), &register(8), Capacity::Free, T0),
        RegisterOutcome::Announce { .. }
    ));
    // One token back after 1/20 s.
    let later = T0 + SECOND / 20;
    assert!(matches!(
        r.register(from, &register(7), Capacity::Free, later),
        RegisterOutcome::Announce { .. }
    ));
    assert_eq!(
        r.register(from, &register(7), Capacity::Free, later),
        RegisterOutcome::Drop(RegisterDrop::SourceRate)
    );
}

#[test]
fn the_driver_rate_is_a_limit() {
    // Tables large enough that only the total decides.
    let mut c = config(&[range([10, 0, 0, 0], 8)]);
    c.config.sources = 1024;
    c.config.pending = 1024;
    let mut r = registrations(c);
    let mut announced = 0;
    for host in 0..300u16 {
        let from = SocketAddr::from(([10, 0, (host >> 8) as u8, host as u8], 40_000));
        match r.register(from, &register(u64::from(host) + 1), Capacity::Free, T0) {
            RegisterOutcome::Announce { .. } => announced += 1,
            RegisterOutcome::Drop(RegisterDrop::Rate) => {}
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(announced, 256);
    assert_eq!(r.counters().dropped_rate, 44);
}

#[test]
fn pending_registrations_are_bounded_globally_and_per_source() {
    let mut r = lan();
    // Per source: two entries, whatever the receiver; a third replaces
    // the source's oldest (karyos#940).
    let from = source(1, 40_000);
    for id in 1..=3 {
        assert!(matches!(
            r.register(from, &register(id), Capacity::Free, T0),
            RegisterOutcome::Announce { .. }
        ));
    }
    let ids = |r: &Harness| -> Vec<u64> {
        r.pending()
            .iter()
            .map(|entry| entry.receiver.receiver_id)
            .collect()
    };
    assert_eq!(ids(&r), [2, 3]);
    assert_eq!(r.counters().pending_replaced, 1);
    // Globally: 32 entries in all.
    let mut id = 10;
    for host in 2..=31u8 {
        id += 1;
        assert!(matches!(
            r.register(source(host, 40_000), &register(id), Capacity::Free, T0),
            RegisterOutcome::Announce { .. }
        ));
    }
    assert_eq!(r.pending().len(), 32);
    // Globally: a 33rd replaces the oldest entry, never grows the table.
    assert!(matches!(
        r.register(source(200, 40_000), &register(999), Capacity::Free, T0 + 1),
        RegisterOutcome::Announce { .. }
    ));
    assert_eq!(r.pending().len(), 32);
    assert_eq!(ids(&r)[..2], [3, 11]);
    assert_eq!(r.counters().pending_replaced, 2);
    assert_eq!(r.counters().dropped_pending_full, 0);
    // An entry not challenged by `join_timeout` is removed, and its room
    // is free again.
    let late = T0 + 1 + 5 * SECOND;
    assert!(matches!(
        r.register(source(201, 40_000), &register(998), Capacity::Free, late),
        RegisterOutcome::Announce { .. }
    ));
    assert_eq!(r.pending().len(), 1);
    assert_eq!(r.counters().expired, 32);
}

#[test]
fn a_full_table_answers_one_err_per_source_per_interval() {
    let mut r = lan();
    let from = source(5, 40_123);
    assert_eq!(
        r.register(from, &register(7), Capacity::Full, T0),
        RegisterOutcome::Refuse { source: from }
    );
    // Nothing is held for a refused registration.
    assert!(r.pending().is_empty());
    for at in 1..20 {
        assert_eq!(
            r.register(from, &register(7), Capacity::Full, T0 + at * SECOND / 20),
            RegisterOutcome::Drop(RegisterDrop::RefusalLimited)
        );
    }
    assert_eq!(
        r.register(from, &register(7), Capacity::Full, T0 + SECOND),
        RegisterOutcome::Refuse { source: from }
    );
    assert_eq!(r.counters().refused_full, 2);
    // Another source is refused on its own interval.
    assert_eq!(
        r.register(source(6, 1), &register(8), Capacity::Full, T0 + SECOND),
        RegisterOutcome::Refuse {
            source: source(6, 1)
        }
    );
}

#[test]
fn the_refusal_table_is_bounded() {
    let mut c = config(&[range([10, 0, 0, 0], 8)]);
    c.config.sources = 4;
    let mut r = registrations(c);
    for host in 1..=4 {
        assert!(matches!(
            r.register(source(host, 1), &register(1), Capacity::Full, T0),
            RegisterOutcome::Refuse { .. }
        ));
    }
    // Every rate entry is busy within the second: a fifth source gets no
    // rate entry and is bound by the driver's total alone, and with no
    // refusal entry free within its interval it gets no ERR.
    assert_eq!(
        r.register(source(5, 1), &register(1), Capacity::Full, T0),
        RegisterOutcome::Drop(RegisterDrop::RefusalLimited)
    );
    assert_eq!(r.counters().source_rates_full, 1);
    // A second later both tables reuse idle entries.
    assert!(matches!(
        r.register(source(5, 1), &register(1), Capacity::Full, T0 + SECOND),
        RegisterOutcome::Refuse { .. }
    ));
}

/// The refusal table's own bound: with `refusal_interval` above one
/// second, the rate entries are idle again before the refusal entries, and
/// a fifth source finds no refusal entry free.
#[test]
fn a_full_refusal_table_drops_a_new_source() {
    let mut c = config(&[range([10, 0, 0, 0], 8)]);
    c.config.sources = 4;
    c.config.refusal_interval = 10 * SECOND;
    let mut r = registrations(c);
    for host in 1..=4 {
        assert!(matches!(
            r.register(source(host, 1), &register(1), Capacity::Full, T0),
            RegisterOutcome::Refuse { .. }
        ));
    }
    assert_eq!(
        r.register(source(5, 1), &register(1), Capacity::Full, T0 + SECOND),
        RegisterOutcome::Drop(RegisterDrop::RefusalLimited)
    );
    assert_eq!(r.counters().dropped_refusal_limited, 1);
    // Once an interval has passed, its entry is reused.
    assert!(matches!(
        r.register(source(5, 1), &register(1), Capacity::Full, T0 + 10 * SECOND),
        RegisterOutcome::Refuse { .. }
    ));
}

/// SPEC.md §6 bounds pending registrations per source address: a source
/// that varies its port, or a spoofer of one victim address, holds no more
/// entries, draws no more replies and no more ERRs than one port would
/// (karyos#940: the rate is the address's too).
#[test]
fn the_per_source_bounds_hold_across_ports() {
    let mut r = lan();
    let mut announced = 0;
    for port in 1..=64u16 {
        if let RegisterOutcome::Announce { .. } = r.register(
            source(77, port),
            &register(u64::from(port)),
            Capacity::Free,
            T0,
        ) {
            announced += 1;
        }
    }
    assert_eq!(announced, 20);
    assert_eq!(r.pending().len(), 2);
    assert_eq!(r.counters().dropped_source_rate, 44);
    assert_eq!(r.counters().pending_replaced, 18);
    let mut r = lan();
    let mut errs = 0;
    for port in 1..=64u16 {
        if let RegisterOutcome::Refuse { .. } =
            r.register(source(77, port), &register(1), Capacity::Full, T0)
        {
            errs += 1;
        }
    }
    assert_eq!(errs, 1);
}

/// Design 9.2: the sender cannot be used to reflect traffic at a third
/// party. A flood of REGISTERs spoofing a victim's address causes, per
/// second, at most `setup_answer_rate` replies of at most 72 bytes to
/// that address, and over many spoofed victims at most the driver's `rate`;
/// a victim outside the allowlist gets nothing.
#[test]
fn the_sender_cannot_be_used_to_reflect_traffic() {
    let mut r = lan();
    let victim = source(77, 53);
    let mut replies = 0usize;
    let mut bytes = 0usize;
    let mut flood_bytes = 0usize;
    // 10 000 REGISTERs within one second, each with a fresh receiver.
    for n in 0..10_000u64 {
        let outcome = r.register(victim, &register(n + 1), Capacity::Free, T0 + n * 100_000);
        flood_bytes += ControlKind::Register.length(0).unwrap();
        if !matches!(outcome, RegisterOutcome::Drop(_)) {
            replies += 1;
            bytes += sent_bytes(outcome);
        }
    }
    // Only two pending entries per source, each new one replacing the
    // oldest, and the address's rate: the victim gets 20 ANNOUNCEs at
    // once and one per 50 ms after (19 within the second), far below the
    // flood.
    assert_eq!(replies, 20 + 19, "{replies}");
    assert_eq!(bytes, replies * 72);
    assert!(bytes * 100 < flood_bytes);
    assert_eq!(r.pending().len(), 2);
    // Retries of one entry are the most a source can draw: the rate.
    let mut r = lan();
    let mut replies = 0;
    for n in 0..10_000u64 {
        let outcome = r.register(victim, &register(1), Capacity::Free, T0 + n * 100_000);
        if !matches!(outcome, RegisterOutcome::Drop(_)) {
            replies += 1;
        }
    }
    // 20 at once, then one per 50 ms over the remaining second (19).
    assert_eq!(replies, 20 + 19, "{replies}");
    // A full table: one ERR per second whatever the flood.
    let mut r = lan();
    let mut errs = 0;
    for n in 0..10_000u64 {
        if let RegisterOutcome::Refuse { .. } =
            r.register(victim, &register(n + 1), Capacity::Full, T0 + n * 100_000)
        {
            errs += 1;
        }
    }
    assert_eq!(errs, 1);
    // Many spoofed victims: the driver's total bounds the sum.
    let mut c = config(&[range([10, 0, 0, 0], 8)]);
    c.config.sources = 4096;
    c.config.pending = 4096;
    let mut r = registrations(c);
    let mut replies = 0;
    for n in 0..4096u64 {
        let from = SocketAddr::from(([10, 1, (n >> 8) as u8, n as u8], 53));
        if !matches!(
            r.register(from, &register(n + 1), Capacity::Free, T0),
            RegisterOutcome::Drop(_)
        ) {
            replies += 1;
        }
    }
    assert_eq!(replies, 256);
    // Outside the allowlist: nothing at all.
    let mut r = lan();
    let outside = SocketAddr::from(([198, 51, 100, 7], 53));
    for n in 0..1_000u64 {
        assert!(matches!(
            r.register(outside, &register(n + 1), Capacity::Free, T0 + n),
            RegisterOutcome::Drop(RegisterDrop::NotAllowed)
        ));
    }
}

/// The driver's registrations are shared by publications on endpoints of
/// either family: each REGISTER is checked against its own publication's
/// family (step 1), so an IPv6 publication admits an IPv6 source and an
/// IPv4 one does not, from one driver state.
#[test]
fn each_publication_checks_its_own_address_family() {
    let mut driver = Registrations::new(RegistrationConfig::default(), T0).unwrap();
    let any_v6 =
        RegistrationAllowlist::new(&[
            AddressRange::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).unwrap()
        ])
        .unwrap();
    let mut v6 = RegistrationPolicy::new(any_v6.clone(), false);
    let mut v4 = RegistrationPolicy::new(any_v6, true);
    let from = SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 9), 40_000));
    assert_eq!(
        driver.register(
            &mut v4,
            from,
            &register(7),
            (Existing::None, Capacity::Free),
            T0,
        ),
        RegisterOutcome::Drop(RegisterDrop::Source)
    );
    assert_eq!(
        driver.register(
            &mut v6,
            from,
            &register(7),
            (Existing::None, Capacity::Free),
            T0,
        ),
        RegisterOutcome::Announce { source: from }
    );
}

/// Design 3.2 step 4: what the publication holds of the receiver drops the
/// REGISTER, each under its own counter, after the retry check and before
/// any pending entry or ERR.
#[test]
fn an_existing_receiver_drops_the_register_under_its_own_reason() {
    let mut r = lan();
    let from = source(5, 40_123);
    let cases = [
        (Existing::Bound, RegisterDrop::Bound),
        (Existing::BootChanged, RegisterDrop::BootChanged),
        (Existing::DuplicateReceiver, RegisterDrop::DuplicateReceiver),
    ];
    for (at, (existing, dropped)) in (0u64..).zip(cases) {
        let outcome = r.registrations.register(
            &mut r.allow,
            from,
            &register(7),
            (existing, Capacity::Full),
            T0 + at,
        );
        assert_eq!(outcome, RegisterOutcome::Drop(dropped));
    }
    assert!(r.pending().is_empty());
    let counters = r.counters();
    assert_eq!(counters.dropped_bound, 1);
    assert_eq!(counters.dropped_boot_changed, 1);
    assert_eq!(counters.duplicate_receiver, 1);
    assert_eq!(counters.refused_full, 0);
    // A pending retry is still a retry: the lookup comes after it.
    assert!(matches!(
        r.register(from, &register(8), Capacity::Free, T0 + 10),
        RegisterOutcome::Announce { .. }
    ));
    let retried = r.registrations.register(
        &mut r.allow,
        from,
        &register(8),
        (Existing::DuplicateReceiver, Capacity::Free),
        T0 + 11,
    );
    assert_eq!(retried, RegisterOutcome::Announce { source: from });
    assert_eq!(r.counters().retried, 1);
}

fn with_required(ids: &[u64]) -> Harness {
    let mut harness = lan();
    harness.allow = harness.allow.clone().with_required(ids).unwrap();
    harness
}

#[test]
fn required_ids_are_nonzero_distinct_and_named() {
    let base = || allow(&[range([10, 0, 0, 0], 8)]);
    assert_eq!(
        base().with_required(&[3, 0]),
        Err(RegistrationConfigError::InvalidRequired { receiver_id: 0 })
    );
    let repeated = base().with_required(&[3, 4, 3]);
    assert_eq!(
        repeated,
        Err(RegistrationConfigError::InvalidRequired { receiver_id: 3 })
    );
    assert!(repeated.unwrap_err().to_string().contains('3'));
    let policy = base().with_required(&[3, 4]).unwrap();
    assert_eq!(policy.required(), &[3, 4]);
    assert!(policy.is_required(4) && !policy.is_required(5));
    assert!(policy.reserved().is_empty());
}

/// MD-17: optional registrants that fill the driver's pending table and
/// the optional slots do not keep a required receiver id out; it takes
/// its reserved entry, never an optional one, and is never refused full.
#[test]
fn a_required_id_registers_past_full_optional_tables() {
    let c = RegistrationConfig {
        pending: 2,
        ..RegistrationConfig::default()
    };
    let mut r = registrations(Setup {
        allow: allow(&[range([10, 0, 0, 0], 8)])
            .with_required(&[42])
            .unwrap(),
        config: c,
    });
    for host in 1..=2 {
        assert!(matches!(
            r.register(
                source(host, 1),
                &register(u64::from(host)),
                Capacity::Free,
                T0
            ),
            RegisterOutcome::Announce { .. }
        ));
    }
    // A third optional entry replaces the oldest: the table never grows.
    assert!(matches!(
        r.register(source(3, 1), &register(3), Capacity::Free, T0),
        RegisterOutcome::Announce { .. }
    ));
    let required = source(9, 1);
    assert_eq!(
        r.register(required, &register(42), Capacity::Full, T0),
        RegisterOutcome::Announce { source: required }
    );
    assert_eq!(r.pending().len(), 2);
    assert_eq!(r.allow.reserved().len(), 1);
    assert_eq!(r.counters().refused_full, 0);
    // Its CHALLENGE takes the reserved entry.
    let taken = r.challenged(required, [42, 1], T0 + 1).unwrap();
    assert_eq!(taken.receiver.receiver_id, 42);
    assert!(r.allow.reserved().is_empty());
}

/// Design 3.2 step 5: spoofed REGISTERs naming a required id from many
/// sources only replace the older of its two reserved entries; the
/// retrying receiver gets an entry back at each retry.
#[test]
fn spoofed_registers_for_a_required_id_replace_only_the_older_entry() {
    let mut r = with_required(&[42]);
    let spoofed = |boot: u64| RspRegister {
        stream_id: STREAM,
        receiver: Receiver {
            receiver_boot_id: [boot, boot],
            receiver_id: 42,
        },
    };
    for host in 1..=8u8 {
        let now = T0 + u64::from(host);
        assert!(matches!(
            r.register(
                source(host, 1),
                &spoofed(u64::from(host)),
                Capacity::Free,
                now
            ),
            RegisterOutcome::Announce { .. }
        ));
        assert!(r.allow.reserved().len() <= REQUIRED_PENDING_PER_ID);
    }
    assert_eq!(r.counters().required_pending_replaced, 6);
    // The two newest are held.
    let held: Vec<u8> = r
        .allow
        .reserved()
        .iter()
        .map(|entry| match entry.source.ip() {
            IpAddr::V4(v4) => v4.octets()[3],
            IpAddr::V6(_) => 0,
        })
        .collect();
    assert_eq!(held, [7, 8]);
    // The real receiver's retry takes an entry back, and its CHALLENGE
    // finds it.
    let real = source(100, 1);
    assert!(matches!(
        r.register(real, &spoofed(100), Capacity::Free, T0 + 20),
        RegisterOutcome::Announce { .. }
    ));
    assert!(r.challenged(real, [100, 100], T0 + 21).is_some());
}

/// The per-source bound applies to the reserved entries too (design 3.2
/// step 5), and they expire at `join_timeout`.
#[test]
fn reserved_entries_count_per_source_and_expire() {
    let mut r = with_required(&[42, 43]);
    let from = source(5, 1);
    let named = |receiver_id: u64, port: u64| RspRegister {
        stream_id: STREAM,
        receiver: Receiver {
            receiver_boot_id: [port, 1],
            receiver_id,
        },
    };
    assert!(matches!(
        r.register(from, &named(42, 1), Capacity::Free, T0),
        RegisterOutcome::Announce { .. }
    ));
    assert!(matches!(
        r.register(from, &named(7, 2), Capacity::Free, T0),
        RegisterOutcome::Announce { .. }
    ));
    // A third replaces the source's oldest, the optional one (the tie
    // goes to the optional table): the source still holds two.
    assert!(matches!(
        r.register(from, &named(43, 3), Capacity::Free, T0 + 1),
        RegisterOutcome::Announce { .. }
    ));
    assert_eq!(r.counters().required_pending_replaced, 1);
    let ids: Vec<u64> = r
        .allow
        .reserved()
        .iter()
        .chain(r.pending())
        .map(|entry| entry.receiver.receiver_id)
        .collect();
    assert_eq!(ids, [42, 43]);
    let join_timeout = RegistrationConfig::default().join_timeout;
    assert!(matches!(
        r.register(from, &named(42, 4), Capacity::Free, T0 + join_timeout),
        RegisterOutcome::Announce { .. }
    ));
    // 42's first entry expired; 43's, a nanosecond younger, not yet.
    assert_eq!(r.counters().expired, 1);
    assert_eq!(r.allow.reserved().len(), 2);
    assert!(r.pending().is_empty());
}

fn named(receiver_id: u64, boot: u64) -> RspRegister {
    RspRegister {
        stream_id: STREAM,
        receiver: Receiver {
            receiver_boot_id: [boot, boot],
            receiver_id,
        },
    }
}

/// karyos#940 item 1: two entries held under a required receiver's own
/// address, on other ports and naming optional ids, do not keep its
/// REGISTER out: it replaces the older, at every retry.
#[test]
fn optional_entries_under_a_required_receivers_address_do_not_lock_it_out() {
    let mut r = with_required(&[42]);
    let real = source(100, 5000);
    let join_timeout = RegistrationConfig::default().join_timeout;
    for (round, now) in [T0, T0 + join_timeout].into_iter().enumerate() {
        for port in [1u16, 2] {
            assert!(matches!(
                r.register(
                    source(100, port),
                    &named(u64::from(port), 1),
                    Capacity::Free,
                    now
                ),
                RegisterOutcome::Announce { .. }
            ));
        }
        assert_eq!(
            r.register(real, &named(42, 100), Capacity::Free, now + 1),
            RegisterOutcome::Announce { source: real }
        );
        assert_eq!(r.counters().required_pending_replaced, 1 + round as u64);
        assert_eq!(r.counters().dropped_source_pending_full, 0);
        // Its CHALLENGE finds its entry; the source holds two at most.
        let held = r
            .pending()
            .iter()
            .chain(r.allow.reserved())
            .filter(|entry| entry.source.ip() == real.ip())
            .count();
        assert_eq!(held, 2);
        assert!(r.challenged(real, [100, 100], now + 2).is_some());
    }
}

/// karyos#940 item 1: two reserved entries of the required id itself,
/// spoofed from its own address, are replaced, not counted against the
/// bound its REGISTER replaces.
#[test]
fn required_entries_under_a_required_receivers_address_are_replaced() {
    let mut r = with_required(&[42]);
    for port in [1u16, 2] {
        assert!(matches!(
            r.register(
                source(100, port),
                &named(42, u64::from(port)),
                Capacity::Free,
                T0
            ),
            RegisterOutcome::Announce { .. }
        ));
    }
    let real = source(100, 5000);
    assert_eq!(
        r.register(real, &named(42, 100), Capacity::Free, T0 + 1),
        RegisterOutcome::Announce { source: real }
    );
    assert_eq!(r.counters().required_pending_replaced, 1);
    // Only the older of its own entries went: one replacement, not two.
    let held: Vec<SocketAddr> = r
        .allow
        .reserved()
        .iter()
        .map(|entry| entry.source)
        .collect();
    assert_eq!(held, [source(100, 2), real]);
    assert!(r.challenged(real, [100, 100], T0 + 2).is_some());
}

/// karyos#940 item 5: spoofed REGISTERs filling the driver's optional
/// pending table do not keep a registrant out: its REGISTER replaces the
/// oldest entry, and a retry of an entry does not refresh it.
#[test]
fn a_full_pending_table_replaces_its_oldest_entry() {
    let mut r = lan();
    for host in 1..=16u8 {
        for port in [1u16, 2] {
            assert!(matches!(
                r.register(
                    source(host, port),
                    &named(u64::from(host) * 10 + u64::from(port), 1),
                    Capacity::Free,
                    T0
                ),
                RegisterOutcome::Announce { .. }
            ));
        }
    }
    assert_eq!(r.pending().len(), 32);
    // A retry of the oldest entry is a retry: it is not moved to the end.
    assert!(matches!(
        r.register(source(1, 1), &named(11, 1), Capacity::Free, T0 + 1),
        RegisterOutcome::Announce { .. }
    ));
    assert_eq!(r.counters().retried, 1);
    let real = source(200, 5000);
    assert_eq!(
        r.register(real, &named(7, 7), Capacity::Free, T0 + 2),
        RegisterOutcome::Announce { source: real }
    );
    assert_eq!(r.pending().len(), 32);
    assert_eq!(r.counters().pending_replaced, 1);
    assert_eq!(r.counters().dropped_pending_full, 0);
    assert!(
        r.pending()
            .iter()
            .all(|entry| entry.receiver.receiver_id != 11)
    );
    assert!(r.challenged(real, [7, 7], T0 + 3).is_some());
}

/// karyos#940 item 4: the per-source rate is the address's, in a table of
/// its own: 64 REGISTERs from one address on as many ports in one second
/// do not make another address's REGISTER drop for its rate.
#[test]
fn registers_from_many_ports_of_one_address_leave_other_addresses_their_rate() {
    let mut r = lan();
    for port in 1..=64u16 {
        let _ = r.register(source(77, port), &named(1, 1), Capacity::Free, T0);
    }
    assert_eq!(r.counters().dropped_source_rate, 44);
    let other = source(50, 5000);
    assert_eq!(
        r.register(other, &named(5, 50), Capacity::Free, T0 + 1),
        RegisterOutcome::Announce { source: other }
    );
    assert_eq!(r.counters().dropped_source_rate, 44);
}

/// karyos#945 review: filling the per-address rate table denies no
/// REGISTER the driver's total admits. 64 allowlisted addresses, one
/// REGISTER every 900 ms each (about 71 a second), keep every entry
/// active, and a required receiver's REGISTER from a 65th address,
/// retried every 100 ms for 5 s, is announced at each retry.
#[test]
fn sixty_four_addresses_filling_the_rate_table_leave_a_new_address_its_register() {
    let mut r = with_required(&[42]);
    let real = source(200, 5000);
    let mut announced = 0;
    for tick in 0..50u64 {
        let now = T0 + tick * SECOND / 10;
        if tick % 9 == 0 {
            for host in 1..=64u8 {
                let _ = r.register(
                    source(host, 1),
                    &named(1000 + u64::from(host), 1),
                    Capacity::Free,
                    now,
                );
            }
        }
        if matches!(
            r.register(real, &named(42, 42), Capacity::Free, now + 1),
            RegisterOutcome::Announce { .. }
        ) {
            announced += 1;
        }
    }
    assert_eq!(announced, 50);
    assert_eq!(r.counters().dropped_source_rate, 0);
    assert_eq!(r.counters().source_rates_full, 50);
}

/// karyos#945 review: an address with no entry in a full rate table is
/// still bound by the driver's total: it draws no more than `rate`.
#[test]
fn an_untracked_address_is_bound_by_the_driver_total() {
    let mut c = config(&[range([10, 0, 0, 0], 8)]);
    c.config.sources = 1;
    c.config.pending = 4096;
    c.config.pending_per_source = 4096;
    let rate = c.config.rate;
    let mut r = registrations(c);
    assert!(matches!(
        r.register(source(1, 1), &named(1, 1), Capacity::Free, T0),
        RegisterOutcome::Announce { .. }
    ));
    let mut announced = 0u64;
    for n in 0..2 * rate {
        if matches!(
            r.register(source(2, 1), &named(n + 2, n + 2), Capacity::Free, T0),
            RegisterOutcome::Announce { .. }
        ) {
            announced += 1;
        }
    }
    assert_eq!(announced, rate - 1);
    assert_eq!(r.counters().dropped_rate, rate + 1);
}

/// MC-6: a CHALLENGE at or after its entry's `join_timeout` takes nothing
/// and would take nothing; one just before does.
#[test]
fn a_challenge_after_join_timeout_takes_no_entry() {
    let mut r = with_required(&[42]);
    let join_timeout = RegistrationConfig::default().join_timeout;
    let (optional, required) = (source(5, 1), source(6, 1));
    assert!(matches!(
        r.register(optional, &named(7, 7), Capacity::Free, T0),
        RegisterOutcome::Announce { .. }
    ));
    assert!(matches!(
        r.register(required, &named(42, 42), Capacity::Free, T0),
        RegisterOutcome::Announce { .. }
    ));
    let late = T0 + join_timeout;
    let both = [(optional, 7), (required, 42)];
    for (from, boot) in both {
        assert!(
            r.registrations
                .would_challenge(&r.allow, STREAM, from, [boot, boot], late - 1)
        );
        assert!(
            !r.registrations
                .would_challenge(&r.allow, STREAM, from, [boot, boot], late)
        );
    }
    for (from, boot) in both {
        assert_eq!(r.challenged(from, [boot, boot], late), None);
    }
    assert_eq!(r.counters().expired, 2);
    assert_eq!(r.counters().challenged, 0);
}

/// The documented [`RegistrationConfigError::InvalidLimit`] of
/// `with_required` (karyos#943): one id more than
/// [`MAX_REGISTRATION_TABLE`] reserved entries hold is refused naming
/// `required`, and the most that fit are accepted.
#[test]
fn more_required_ids_than_the_table_holds_are_refused_naming_required() {
    let most = u64::try_from(MAX_REGISTRATION_TABLE / REQUIRED_PENDING_PER_ID).unwrap();
    let fit: Vec<u64> = (1..=most).collect();
    let over: Vec<u64> = (1..=most + 1).collect();
    let base = || allow(&[range([10, 0, 0, 0], 8)]);
    assert!(base().with_required(&fit).is_ok());
    assert_eq!(
        base().with_required(&over).map(|_| ()),
        Err(RegistrationConfigError::InvalidLimit { field: "required" })
    );
}
