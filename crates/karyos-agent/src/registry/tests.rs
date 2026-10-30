// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use super::*;

use proptest::prelude::*;

const UID: u32 = 1000;

/// A product puts an entry and reads it back; a second put makes version
/// 2, and an instant before it still joins against version 1.
#[test]
fn a_put_is_versioned_and_read_at_an_instant() {
    let mut registry = Registry::new(10);
    assert_eq!(
        registry.put(
            0,
            Kind::Point,
            "md.tick",
            "venue=xnas instrument=aapl",
            UID,
            100
        ),
        Ok(1)
    );
    assert_eq!(
        registry.put(
            0,
            Kind::Point,
            "md.tick",
            "venue=xnys instrument=aapl",
            UID,
            200
        ),
        Ok(2)
    );
    let entry = registry.get(0, Kind::Point, "md.tick").unwrap();
    let old = entry.at(150).unwrap();
    assert_eq!(old.number, 1);
    assert_eq!((old.valid_from, old.valid_to), (100, Some(200)));
    assert_eq!(
        old.attributes().collect::<Vec<_>>(),
        [("venue", "xnas"), ("instrument", "aapl")]
    );
    let new = entry.at(200).unwrap();
    assert_eq!(
        (new.number, new.valid_to, new.registered_by),
        (2, None, UID)
    );
    // Before the first version, nothing was in force.
    assert!(entry.at(99).is_none());
    assert!(!entry.before_history(99));
    // Another driver's key of the same name is another entry.
    assert!(registry.get(1, Kind::Point, "md.tick").is_none());
}

/// A retire ends the current version and keeps the history; a retire of
/// a key without a current version is not found; a put after a retire
/// goes on numbering.
#[test]
fn a_retire_ends_the_current_version() {
    let mut registry = Registry::new(0);
    registry
        .put(0, Kind::Counter, "orders", "desk=a", UID, 10)
        .unwrap();
    assert_eq!(registry.retire(0, Kind::Counter, "orders", 20), Ok(1));
    let entry = registry.get(0, Kind::Counter, "orders").unwrap();
    assert_eq!(entry.at(15).unwrap().number, 1);
    assert!(entry.at(20).is_none());
    assert_eq!(entry.retired_ns, Some(20));
    assert_eq!(
        registry.retire(0, Kind::Counter, "orders", 30),
        Err(Refusal::NotFound)
    );
    assert_eq!(
        registry.retire(0, Kind::Counter, "nothing", 30),
        Err(Refusal::NotFound)
    );
    assert_eq!(
        registry.put(0, Kind::Counter, "orders", "desk=b", UID, 40),
        Ok(2)
    );
    assert_eq!(
        registry.get(0, Kind::Counter, "orders").unwrap().retired_ns,
        None
    );
}

/// A key keeps its newest versions only; the dropped ones are counted,
/// and an instant before the kept history says so.
#[test]
fn old_versions_are_dropped_and_counted() {
    let mut registry = Registry::new(0);
    for at in 1..=u64::try_from(MAX_VERSIONS).unwrap() + 2 {
        registry
            .put(0, Kind::Stream, "7", &format!("v={at}"), UID, at * 10)
            .unwrap();
    }
    let entry = registry.get(0, Kind::Stream, "7").unwrap();
    assert_eq!(entry.versions.len(), MAX_VERSIONS);
    assert_eq!(entry.history_dropped, 2);
    assert_eq!(entry.versions.front().unwrap().number, 3);
    assert!(entry.at(15).is_none());
    assert!(entry.before_history(15));
}

/// Instants never go back within a key, whatever the clock passed.
#[test]
fn instants_never_go_back() {
    let mut registry = Registry::new(0);
    registry.put(0, Kind::Stream, "1", "a=1", UID, 100).unwrap();
    registry.put(0, Kind::Stream, "1", "a=2", UID, 50).unwrap();
    let entry = registry.get(0, Kind::Stream, "1").unwrap();
    let [first, second] = [&entry.versions[0], &entry.versions[1]];
    assert_eq!(first.valid_to, Some(100));
    assert_eq!(second.valid_from, 100);
}

/// Each bound has its typed refusal, and a malformed key or attribute its
/// own; nothing is kept from a refused put.
#[test]
fn each_bound_and_shape_is_refused() {
    let mut registry = Registry::new(0);
    let above = |dimension: &'static str, bound: usize| Refusal::Above {
        dimension,
        bound: bound as u64,
    };
    let many = (0..=MAX_ATTRIBUTES)
        .map(|index| format!("a{index}=x"))
        .collect::<Vec<_>>()
        .join(" ");
    let rows: [(Kind, String, String, Refusal); 14] = [
        (
            Kind::Point,
            "p".into(),
            many,
            above("join.attributes_per_entry", MAX_ATTRIBUTES),
        ),
        (
            Kind::Point,
            "p".into(),
            format!("{}=x", "n".repeat(MAX_NAME_BYTES + 1)),
            above("join.name_bytes", MAX_NAME_BYTES),
        ),
        (
            Kind::Point,
            "p".into(),
            format!("n={}", "v".repeat(MAX_VALUE_BYTES + 1)),
            above("join.value_bytes", MAX_VALUE_BYTES),
        ),
        (
            Kind::Point,
            "k".repeat(MAX_KEY_BYTES + 1),
            "n=v".into(),
            above("join.key_bytes", MAX_KEY_BYTES),
        ),
        (
            Kind::Point,
            "p".into(),
            "Name=v".into(),
            Refusal::Bad("attribute name"),
        ),
        (
            Kind::Point,
            "p".into(),
            "=v".into(),
            Refusal::Bad("attribute name"),
        ),
        (
            Kind::Point,
            "p".into(),
            "n=".into(),
            Refusal::Bad("attribute value"),
        ),
        (
            Kind::Point,
            "p".into(),
            "n=a=b".into(),
            Refusal::Bad("attribute value"),
        ),
        (
            Kind::Point,
            "p".into(),
            "n=é".into(),
            Refusal::Bad("attribute value"),
        ),
        (
            Kind::Point,
            "p".into(),
            "n=v n=w".into(),
            Refusal::Bad("attribute repeated"),
        ),
        (
            Kind::Point,
            "p".into(),
            "n".into(),
            Refusal::Bad("attribute"),
        ),
        (
            Kind::Point,
            "p".into(),
            String::new(),
            Refusal::Bad("attribute"),
        ),
        (Kind::Stream, "07".into(), "n=v".into(), Refusal::Bad("key")),
        (
            Kind::Point,
            "a\tb".into(),
            "n=v".into(),
            Refusal::Bad("key"),
        ),
    ];
    for (kind, key, attributes, refusal) in rows {
        assert_eq!(
            registry.put(0, kind, &key, &attributes, UID, 1),
            Err(refusal),
            "{key:?} {attributes:?}"
        );
    }
    assert!(registry.is_empty());
    // At the bounds, accepted.
    let most = (0..MAX_ATTRIBUTES)
        .map(|index| {
            format!(
                "{}{index:02}={}",
                "n".repeat(MAX_NAME_BYTES - 2),
                "v".repeat(MAX_VALUE_BYTES)
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(
        registry.put(0, Kind::Point, &"k".repeat(MAX_KEY_BYTES), &most, UID, 1),
        Ok(1)
    );
    assert_eq!(
        registry.put(0, Kind::Stream, "-2147483648", "n=v", UID, 1),
        Ok(1)
    );
}

/// The key bounds: a full driver or a full registry refuses a new key
/// with its bound, unless a retired key can be evicted, the oldest first;
/// a new version of a held key is always accepted.
#[test]
fn the_key_bounds_refuse_or_evict_the_oldest_retired() {
    let mut registry = Registry::new(0);
    for index in 0..MAX_KEYS_PER_DRIVER {
        registry
            .put(0, Kind::Counter, &format!("c{index}"), "n=v", UID, 1)
            .unwrap();
    }
    assert_eq!(
        registry.put(0, Kind::Counter, "one-more", "n=v", UID, 2),
        Err(Refusal::Above {
            dimension: "join.keys_per_driver",
            bound: MAX_KEYS_PER_DRIVER as u64,
        })
    );
    // MAX_KEYS equals the per-driver bound: another driver meets the
    // registry's.
    assert_eq!(
        registry.put(1, Kind::Counter, "c0", "n=v", UID, 2),
        Err(Refusal::Above {
            dimension: "join.keys",
            bound: MAX_KEYS as u64,
        })
    );
    assert_eq!(registry.put(0, Kind::Counter, "c5", "n=w", UID, 3), Ok(2));
    registry.retire(0, Kind::Counter, "c9", 10).unwrap();
    registry.retire(0, Kind::Counter, "c3", 5).unwrap();
    assert_eq!(
        registry.put(0, Kind::Counter, "one-more", "n=v", UID, 11),
        Ok(1)
    );
    assert_eq!(registry.evicted(), 1);
    assert!(registry.get(0, Kind::Counter, "c3").is_none());
    assert!(registry.get(0, Kind::Counter, "c9").is_some());
    assert_eq!(registry.len(), MAX_KEYS);
}

/// Each counter at `u64::MAX` refuses the put that would pass it, as a
/// typed overflow, and the refused put changes nothing (SPEC §14).
#[test]
fn a_counter_at_its_maximum_refuses_and_changes_nothing() {
    let mut registry = Registry::new(0);
    registry.put(0, Kind::Point, "p", "n=v", UID, 1).unwrap();
    registry
        .entries
        .get_mut(&(0, Kind::Point, "p".to_owned()))
        .unwrap()
        .versions
        .back_mut()
        .unwrap()
        .number = u64::MAX;
    let before = registry.get(0, Kind::Point, "p").cloned();
    assert_eq!(
        registry.put(0, Kind::Point, "p", "n=w", UID, 2),
        Err(Refusal::Overflow("version number"))
    );
    assert_eq!(registry.get(0, Kind::Point, "p").cloned(), before);

    for index in 0..MAX_VERSIONS {
        registry
            .put(0, Kind::Point, "h", &format!("n=v{index}"), UID, 1)
            .unwrap();
    }
    registry
        .entries
        .get_mut(&(0, Kind::Point, "h".to_owned()))
        .unwrap()
        .history_dropped = u64::MAX;
    let before = registry.get(0, Kind::Point, "h").cloned();
    assert_eq!(
        registry.put(0, Kind::Point, "h", "n=w", UID, 2),
        Err(Refusal::Overflow("history_dropped"))
    );
    assert_eq!(registry.get(0, Kind::Point, "h").cloned(), before);

    let mut registry = Registry::new(0);
    for index in 0..MAX_KEYS_PER_DRIVER {
        registry
            .put(0, Kind::Counter, &format!("c{index}"), "n=v", UID, 1)
            .unwrap();
    }
    registry.retire(0, Kind::Counter, "c3", 5).unwrap();
    registry.evicted = u64::MAX;
    assert_eq!(
        registry.put(0, Kind::Counter, "one-more", "n=v", UID, 6),
        Err(Refusal::Overflow("evicted"))
    );
    assert_eq!(registry.evicted(), u64::MAX);
    assert!(registry.get(0, Kind::Counter, "c3").is_some());
    assert!(registry.get(0, Kind::Counter, "one-more").is_none());
    assert_eq!(registry.len(), MAX_KEYS_PER_DRIVER);
}

/// A list pages a driver's keys in order, and only that driver's.
#[test]
fn a_list_pages_one_drivers_keys() {
    let mut registry = Registry::new(0);
    for index in 0..LIST_PAGE + 3 {
        registry
            .put(0, Kind::Counter, &format!("c{index:03}"), "n=v", UID, 1)
            .unwrap();
    }
    registry.put(0, Kind::Stream, "5", "n=v", UID, 1).unwrap();
    registry.put(1, Kind::Stream, "5", "n=v", UID, 1).unwrap();
    let (first, more) = registry.list(0, None);
    assert!(more);
    assert_eq!(first.len(), LIST_PAGE);
    assert_eq!((first[0].kind, first[0].key.as_str()), (Kind::Stream, "5"));
    let last = first.last().unwrap();
    let (second, more) = registry.list(0, Some((last.kind, &last.key)));
    assert!(!more);
    assert_eq!(second.len(), 4);
    assert_eq!(second.last().unwrap().key, format!("c{:03}", LIST_PAGE + 2));
    let (other, _) = registry.list(1, None);
    assert_eq!(other.len(), 1);
}

/// Two registries have different generations, and the worst case of
/// the memory the entries hold is within 8 MiB.
#[test]
fn generations_differ_and_memory_is_bounded() {
    assert_ne!(Registry::new(0).generation(), Registry::new(0).generation());
    assert_eq!(Registry::new(42).since_ns(), 42);
    assert_eq!(MAX_MEMORY_BYTES, 6_864_896);
    const { assert!(MAX_MEMORY_BYTES <= 8 << 20) };
}

/// Any text: a key or attribute bytes, ASCII and not, spaces and `=`
/// included, around each bound.
fn text(max: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            4 => proptest::char::range('a', 'z'),
            1 => proptest::char::range('0', '9'),
            1 => Just('='),
            1 => Just(' '),
            1 => Just('.'),
            1 => Just('A'),
            1 => Just('é'),
            1 => Just('\u{0}'),
        ],
        0..=max,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

/// Lowercase words up to `max` bytes: keys and names mostly accepted.
fn word(max: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::char::range('a', 'z'), 1..=max)
        .prop_map(|chars| chars.into_iter().collect())
}

/// Attributes mostly well formed, their counts and lengths around each
/// bound.
fn attributes() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        (word(MAX_NAME_BYTES + 1), text(MAX_VALUE_BYTES + 1)),
        0..=MAX_ATTRIBUTES + 1,
    )
    .prop_map(|pairs| {
        pairs
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    })
}

fn kind() -> impl Strategy<Value = Kind> {
    prop_oneof![Just(Kind::Stream), Just(Kind::Point), Just(Kind::Counter)]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Whatever is put (karyos#893): it never panics; what is kept holds
    /// every bound; and a refused put changes nothing a reader sees.
    #[test]
    fn a_put_keeps_its_bounds_and_a_refused_one_changes_nothing(
        puts in proptest::collection::vec(
            (
                0..2usize,
                kind(),
                prop_oneof![word(MAX_KEY_BYTES + 1), text(MAX_KEY_BYTES + 2)],
                prop_oneof![attributes(), text(2 * MAX_VALUE_BYTES)],
            ),
            1..16,
        ),
    ) {
        let mut registry = Registry::new(0);
        for (now, (driver, kind, key, attributes)) in (1u64..).zip(&puts) {
            let before = registry.get(*driver, *kind, key).cloned();
            let (len, evicted) = (registry.len(), registry.evicted());
            match registry.put(*driver, *kind, key, attributes, UID, now) {
                Ok(number) => {
                    let entry = registry.get(*driver, *kind, key).unwrap();
                    prop_assert_eq!(entry.versions.back().unwrap().number, number);
                    prop_assert!(entry.key.len() <= MAX_KEY_BYTES);
                    prop_assert!(entry.versions.len() <= MAX_VERSIONS);
                    let kept: Vec<_> = entry.versions.back().unwrap().attributes().collect();
                    prop_assert!(!kept.is_empty() && kept.len() <= MAX_ATTRIBUTES);
                    for (name, value) in kept {
                        prop_assert!(!name.is_empty() && name.len() <= MAX_NAME_BYTES);
                        prop_assert!(value.len() <= MAX_VALUE_BYTES);
                    }
                }
                Err(_) => {
                    prop_assert_eq!(registry.get(*driver, *kind, key).cloned(), before);
                    prop_assert_eq!(registry.len(), len);
                    prop_assert_eq!(registry.evicted(), evicted);
                }
            }
            prop_assert!(registry.len() <= MAX_KEYS);
        }
    }
}
