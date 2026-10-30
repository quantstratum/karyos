// SPDX-License-Identifier: Apache-2.0

//! The join registry's memory bound (karyos#893): filled to every bound,
//! the registry holds no more than `join.memory_bytes`, counted by the
//! allocator in layout bytes.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used)]

use karyos_agent::registry::{
    Kind, MAX_ATTRIBUTES, MAX_KEY_BYTES, MAX_KEYS, MAX_MEMORY_BYTES, MAX_NAME_BYTES,
    MAX_VALUE_BYTES, MAX_VERSIONS, Registry,
};
use karyos_sys::alloc_count::{CountingAllocator, count_bytes};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Every key at its longest, each with every version kept at the most
/// attributes of the longest names and values, and one more put per key
/// so a version is dropped: what it holds, and the most it held while
/// filling, stay within the bound.
#[test]
fn a_full_registry_holds_no_more_than_its_memory_bound() {
    let keys: Vec<String> = (0..MAX_KEYS)
        .map(|index| format!("{index:0>width$}", width = MAX_KEY_BYTES))
        .collect();
    let attributes: Vec<String> = (0..=MAX_VERSIONS)
        .map(|version| {
            (0..MAX_ATTRIBUTES)
                .map(|index| {
                    let name = format!("{index:a>width$}", width = MAX_NAME_BYTES)
                        .replace(|c: char| c.is_ascii_digit(), "n");
                    let name = format!("{}{}", &name[..MAX_NAME_BYTES - 2], letters(index));
                    format!(
                        "{name}={}",
                        "v".repeat(MAX_VALUE_BYTES - 1) + &version.to_string()
                    )
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    let (registry, bytes) = count_bytes(|| {
        let mut registry = Registry::new(0);
        for (now, key) in (1u64..).zip(&keys) {
            for text in &attributes {
                registry.put(0, Kind::Point, key, text, 1000, now).unwrap();
            }
        }
        registry
    });
    assert_eq!(registry.len(), MAX_KEYS);
    let entry = registry.get(0, Kind::Point, &keys[0]).unwrap();
    assert_eq!(entry.versions.len(), MAX_VERSIONS);
    assert_eq!(entry.history_dropped, 1);
    assert_eq!(entry.versions[0].attributes().count(), MAX_ATTRIBUTES);
    let bound = i128::try_from(MAX_MEMORY_BYTES).unwrap();
    assert!(
        bytes.net <= bound,
        "held {} > {bound} (peak {})",
        bytes.net,
        bytes.peak
    );
    assert!(bytes.peak <= bound, "peak {} > {bound}", bytes.peak);
    // Measured, for the record (karyos#893): the bound is not loose by
    // more than a quarter.
    assert!(bytes.net * 5 >= bound * 4, "held {} << {bound}", bytes.net);
}

/// Two distinct lowercase letters for `index`, so names differ.
fn letters(index: usize) -> String {
    let a = b'a' + u8::try_from(index / 26).unwrap();
    let b = b'a' + u8::try_from(index % 26).unwrap();
    String::from_utf8(vec![a, b]).unwrap()
}
