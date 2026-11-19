// SPDX-License-Identifier: Apache-2.0

//! The join metadata registry (karyos#736; Insights ADR-0022, "Versioned
//! metadata joins through a public, agent-visible registry serve stable
//! dimensions"; quantstratum-docs: karyos/design/observability-and-tools.md,
//! Join metadata).
//!
//! - **What it holds.** Metadata a product supplies about a stable core
//!   identity of one driver: a wire stream id, an application trace point
//!   label (R-CORE-1) or an application counter label (R-CORE-3). An entry
//!   is a set of bounded `name=value` attributes. Its meaning is the
//!   product's; the agent checks its shape and bounds and nothing else.
//! - **Versions.** Each put on a key makes a new version, numbered per key
//!   from 1, valid from the agent's host `CLOCK_MONOTONIC` nanoseconds at
//!   acceptance until the next put or the retire. A read names an instant
//!   and gets the version in force then. A key keeps its newest
//!   [`MAX_VERSIONS`] versions; older ones are dropped and counted.
//! - **Bounds.** [`MAX_KEYS`] keys in all and [`MAX_KEYS_PER_DRIVER`] per
//!   driver, each refused past its bound with the bound's name. When the
//!   registry is full, a put of a new key first evicts the key retired
//!   longest ago, if any, and counts it. The worst case of the memory it
//!   holds is [`MAX_MEMORY_BYTES`].
//! - **Lifetime.** In memory only: an agent's restart starts an empty
//!   registry with a new [`Registry::generation`], and its times compare
//!   only within one generation. A driver's restart changes nothing: the
//!   keys are names the restarted driver registers again.
//! - **Not evidence.** An entry is an assertion of the uid that put it,
//!   never proof of ownership: "A shared publication does not identify a
//!   strategy" (ADR-0022). Whether its identity is present, and whether a
//!   stream is shared, is the agent's own point-in-time observation, given
//!   at each read.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::hash::{BuildHasher, Hasher};

/// Keys in the whole registry at most.
pub const MAX_KEYS: usize = 1024;
/// Keys of one driver at most.
pub const MAX_KEYS_PER_DRIVER: usize = 1024;
/// Versions one key keeps.
pub const MAX_VERSIONS: usize = 4;
/// Attributes of one version at most.
pub const MAX_ATTRIBUTES: usize = 16;
/// The longest attribute name, in bytes: `[a-z0-9_.]`.
pub const MAX_NAME_BYTES: usize = 32;
/// The longest attribute value, in bytes: printable ASCII other than
/// space and `=`.
pub const MAX_VALUE_BYTES: usize = 64;
/// The longest key, in bytes: a counter label's bound.
pub const MAX_KEY_BYTES: usize = karyos_sys::counters::MAX_LABEL_LENGTH;
/// The keys one `join-list` reply holds at most.
pub const LIST_PAGE: usize = 64;
/// The bytes one version holds at most besides its fixed fields: its
/// attributes as `name=value`, separated by spaces.
const MAX_ATTRIBUTE_TEXT: usize = MAX_ATTRIBUTES * (MAX_NAME_BYTES + 1 + MAX_VALUE_BYTES + 1);
/// The fixed size of one version in its key's queue (the queue holds
/// exactly [`MAX_VERSIONS`]); its attribute text is held exactly, as
/// accepted.
const VERSION_BYTES: usize = std::mem::size_of::<Version>();
/// One key besides its versions: its text twice (the map's key and the
/// entry's) and its share of the map's nodes. A node holds up to 11 keys
/// and at least 5 (the root excepted), and the inner nodes are fewer than
/// a fifth of the leaves, so a key's share is under 3 slots of key and
/// entry (karyos#893).
const KEY_BYTES: usize = 2 * MAX_KEY_BYTES + 3 * std::mem::size_of::<(Key, Entry)>();
/// The most memory the registry's entries hold:
/// `MAX_KEYS x (KEY_BYTES + MAX_VERSIONS x (VERSION_BYTES + MAX_ATTRIBUTE_TEXT))`,
/// in layout bytes; 7 208 960 bytes (6.9 MiB) on 64-bit targets. The
/// counting allocator measures a registry filled to every bound at
/// 7 057 552 held and 7 059 375 at its peak (`tests/registry_memory.rs`).
pub const MAX_MEMORY_BYTES: usize =
    MAX_KEYS * (KEY_BYTES + MAX_VERSIONS * (VERSION_BYTES + MAX_ATTRIBUTE_TEXT));

/// What a key names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// A wire stream id.
    Stream,
    /// An application trace point label (R-CORE-1).
    Point,
    /// An application counter label (R-CORE-3).
    Counter,
}

impl Kind {
    /// The kind named `name`: `stream`, `point` or `counter`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "stream" => Self::Stream,
            "point" => Self::Point,
            "counter" => Self::Counter,
            _ => return None,
        })
    }

    /// Its name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stream => "stream",
            Self::Point => "point",
            Self::Counter => "counter",
        }
    }
}

/// A key: the driver it belongs to, by its index in the agent's
/// configuration, what it names and the name.
type Key = (usize, Kind, String);

/// One version of an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// Its number, from 1 per key.
    pub number: u64,
    /// The uid that put it, or, for a relayed request (karyos#708), the
    /// principal's operator id.
    pub registered_by: u32,
    /// The relay that carried the request (karyos#708), by its configured
    /// id; 0 for a request on the local socket. Kept apart from
    /// `registered_by`, as the journal keeps it.
    pub relay: u64,
    /// Host `CLOCK_MONOTONIC` nanoseconds from which it is in force.
    pub valid_from: u64,
    /// Until which it is in force, exclusive; `None` while current.
    pub valid_to: Option<u64>,
    /// Its attributes, `name=value` separated by single spaces, as checked.
    attributes: String,
}

impl Version {
    /// Its attributes, name and value, in the order they were put.
    pub fn attributes(&self) -> impl Iterator<Item = (&str, &str)> {
        self.attributes
            .split(' ')
            .filter_map(|attribute| attribute.split_once('='))
    }
}

/// An entry: a key's kept versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// What it names.
    pub kind: Kind,
    /// The name.
    pub key: String,
    /// Its newest versions, oldest first.
    pub versions: VecDeque<Version>,
    /// Versions dropped for [`MAX_VERSIONS`].
    pub history_dropped: u64,
    /// When it was retired, if its newest version has ended.
    pub retired_ns: Option<u64>,
}

impl Entry {
    /// The version in force at `at`, if a kept one was.
    #[must_use]
    pub fn at(&self, at: u64) -> Option<&Version> {
        self.versions
            .iter()
            .find(|version| version.valid_from <= at && version.valid_to.is_none_or(|to| at < to))
    }

    /// Whether `at` is before its oldest kept version: what was in force
    /// then may have been dropped.
    #[must_use]
    pub fn before_history(&self, at: u64) -> bool {
        self.history_dropped > 0
            && self
                .versions
                .front()
                .is_some_and(|oldest| at < oldest.valid_from)
    }
}

/// Why a put or a retire was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Past a bound: its `limits` dimension and value.
    Above {
        /// The dimension.
        dimension: &'static str,
        /// Its bound.
        bound: u64,
    },
    /// Malformed: what was wrong.
    Bad(&'static str),
    /// No current entry under the key.
    NotFound,
    /// A counter would pass `u64::MAX`: which one. Nothing was changed
    /// (SPEC §14).
    Overflow(&'static str),
}

/// What the agent observes of an entry's identity at a read: a
/// point-in-time fact, never part of the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Presence {
    /// Whether the identity is in the driver now; `None` when the agent
    /// cannot tell (a stream, whose wire id no cell carries, or a driver
    /// not attached).
    pub present: Option<bool>,
    /// How many client cells of that type and label hold it now (one
    /// client may hold several); `None` when the agent cannot tell.
    pub holders: Option<u64>,
}

impl Presence {
    /// Whether more than one client cell is observed now; `None` when
    /// unknown.
    #[must_use]
    pub fn shared(self) -> Option<bool> {
        self.holders.map(|holders| holders > 1)
    }
}

/// A `join-get` answer: the version in force at `at`, if any.
#[derive(Debug)]
pub struct Read<'a> {
    /// The registry's generation.
    pub generation: u64,
    /// When the registry started.
    pub since_ns: u64,
    /// The driver's directory.
    pub dir: &'a std::path::Path,
    /// What the key names.
    pub kind: Kind,
    /// The key.
    pub key: &'a str,
    /// The instant asked about.
    pub at: u64,
    /// The entry, if the key has one.
    pub entry: Option<&'a Entry>,
    /// What the agent observes of the identity now.
    pub presence: Presence,
}

/// A `join-list` page.
#[derive(Debug)]
pub struct Page<'a> {
    /// The registry's generation.
    pub generation: u64,
    /// When the registry started.
    pub since_ns: u64,
    /// Retired keys evicted so far.
    pub evicted: u64,
    /// The driver's directory.
    pub dir: &'a std::path::Path,
    /// Its entries in key order, with what the agent observes of each.
    pub entries: Vec<(&'a Entry, Presence)>,
    /// Whether more follow the last one.
    pub more: bool,
}

/// Why a registry request was not served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinError {
    /// No configured driver has that directory.
    UnknownDriver,
    /// The registry's refusal.
    Refused(Refusal),
}

/// The registry.
#[derive(Debug)]
pub struct Registry {
    entries: BTreeMap<Key, Entry>,
    generation: u64,
    since_ns: u64,
    evicted: u64,
}

impl Registry {
    /// An empty registry started at `now` (host `CLOCK_MONOTONIC`
    /// nanoseconds), with a random generation.
    #[must_use]
    pub fn new(now: u64) -> Self {
        let generation = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        Self {
            entries: BTreeMap::new(),
            generation,
            since_ns: now,
            evicted: 0,
        }
    }

    /// This registry's generation, new at each agent start: versions and
    /// instants compare only within one generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// When it started.
    #[must_use]
    pub const fn since_ns(&self) -> u64 {
        self.since_ns
    }

    /// Retired keys evicted to make room for new ones.
    #[must_use]
    pub const fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Keys held, retired ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether it holds no key.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Puts a new version of driver `driver`'s `kind` `key` with
    /// `attributes` (`name=value` separated by single spaces), by `uid`, at
    /// `now`; answers its number.
    ///
    /// # Errors
    ///
    /// [`Refusal::Bad`] for a malformed key or attribute,
    /// [`Refusal::Above`] past a bound, and [`Refusal::Overflow`] when the
    /// version number, `history_dropped` or `evicted` would pass
    /// `u64::MAX`; a refused put changes nothing.
    pub fn put(
        &mut self,
        driver: usize,
        kind: Kind,
        key: &str,
        attributes: &str,
        uid: u32,
        now: u64,
    ) -> Result<u64, Refusal> {
        self.put_relayed(driver, kind, key, attributes, (uid, 0), now)
    }

    /// [`Registry::put`] for `by`: the operator (a uid, or a relayed
    /// principal's operator id) and the relay's id, 0 for none
    /// (karyos#708).
    ///
    /// # Errors
    ///
    /// As [`Registry::put`].
    pub fn put_relayed(
        &mut self,
        driver: usize,
        kind: Kind,
        key: &str,
        attributes: &str,
        by: (u32, u64),
        now: u64,
    ) -> Result<u64, Refusal> {
        let (uid, relay) = by;
        check_key(kind, key)?;
        let attributes = check_attributes(attributes)?;
        let id = (driver, kind, key.to_owned());
        // Every counter is checked before anything changes, so a refused
        // put leaves the registry as it was.
        let (number, dropped) = match self.entries.get(&id) {
            Some(entry) => (
                entry
                    .versions
                    .back()
                    .map_or(Some(1), |last| last.number.checked_add(1)),
                if entry.versions.len() == MAX_VERSIONS {
                    entry.history_dropped.checked_add(1)
                } else {
                    Some(entry.history_dropped)
                },
            ),
            None => {
                self.make_room(driver)?;
                (Some(1), Some(0))
            }
        };
        let number = number.ok_or(Refusal::Overflow("version number"))?;
        let dropped = dropped.ok_or(Refusal::Overflow("history_dropped"))?;
        let entry = self.entries.entry(id).or_insert_with(|| Entry {
            kind,
            key: key.to_owned(),
            versions: VecDeque::with_capacity(MAX_VERSIONS),
            history_dropped: 0,
            retired_ns: None,
        });
        // The instants never go back within a key, whatever the clock read.
        let now = entry.versions.back().map_or(now, |last| {
            now.max(last.valid_to.unwrap_or(last.valid_from))
        });
        if let Some(last) = entry.versions.back_mut()
            && last.valid_to.is_none()
        {
            last.valid_to = Some(now);
        }
        if entry.versions.len() == MAX_VERSIONS {
            entry.versions.pop_front();
        }
        entry.history_dropped = dropped;
        entry.versions.push_back(Version {
            number,
            registered_by: uid,
            relay,
            valid_from: now,
            valid_to: None,
            attributes,
        });
        entry.retired_ns = None;
        Ok(number)
    }

    /// Ends the current version of driver `driver`'s `kind` `key` at `now`;
    /// answers its number. The key keeps its history.
    ///
    /// # Errors
    ///
    /// [`Refusal::Bad`] for a malformed key, [`Refusal::NotFound`] when the
    /// key has no current version.
    pub fn retire(
        &mut self,
        driver: usize,
        kind: Kind,
        key: &str,
        now: u64,
    ) -> Result<u64, Refusal> {
        check_key(kind, key)?;
        let entry = self
            .entries
            .get_mut(&(driver, kind, key.to_owned()))
            .ok_or(Refusal::NotFound)?;
        let current = entry
            .versions
            .back_mut()
            .filter(|version| version.valid_to.is_none())
            .ok_or(Refusal::NotFound)?;
        let now = now.max(current.valid_from);
        current.valid_to = Some(now);
        entry.retired_ns = Some(now);
        Ok(current.number)
    }

    /// Driver `driver`'s entry for `kind` `key`, if it has one.
    #[must_use]
    pub fn get(&self, driver: usize, kind: Kind, key: &str) -> Option<&Entry> {
        self.entries.get(&(driver, kind, key.to_owned()))
    }

    /// Up to [`LIST_PAGE`] of driver `driver`'s entries in key order, after
    /// `after` when given, and whether more follow.
    #[must_use]
    pub fn list(&self, driver: usize, after: Option<(Kind, &str)>) -> (Vec<&Entry>, bool) {
        use std::ops::Bound;
        let low = match after {
            Some((kind, key)) => Bound::Excluded((driver, kind, key.to_owned())),
            None => Bound::Included((driver, Kind::Stream, String::new())),
        };
        let mut page: Vec<&Entry> = self
            .entries
            .range((low, Bound::Unbounded))
            .take_while(|((owner, _, _), _)| *owner == driver)
            .take(LIST_PAGE + 1)
            .map(|(_, entry)| entry)
            .collect();
        let more = page.len() > LIST_PAGE;
        page.truncate(LIST_PAGE);
        (page, more)
    }

    /// Room for one more key of `driver`: past a bound, the key retired
    /// longest ago (of that driver when the driver's bound is the one
    /// reached) is evicted; with none retired, the put is refused.
    fn make_room(&mut self, driver: usize) -> Result<(), Refusal> {
        let of_driver = self
            .entries
            .keys()
            .filter(|(owner, _, _)| *owner == driver)
            .count();
        let (full, dimension, bound) = if of_driver >= MAX_KEYS_PER_DRIVER {
            (true, "join.keys_per_driver", MAX_KEYS_PER_DRIVER)
        } else if self.entries.len() >= MAX_KEYS {
            (true, "join.keys", MAX_KEYS)
        } else {
            (false, "", 0)
        };
        if !full {
            return Ok(());
        }
        let per_driver = dimension == "join.keys_per_driver";
        let oldest = self
            .entries
            .iter()
            .filter(|((owner, _, _), _)| !per_driver || *owner == driver)
            .filter_map(|(id, entry)| entry.retired_ns.map(|at| (at, id.clone())))
            .min_by_key(|(at, _)| *at)
            .map(|(_, id)| id);
        match oldest {
            Some(id) => {
                self.evicted = self
                    .evicted
                    .checked_add(1)
                    .ok_or(Refusal::Overflow("evicted"))?;
                self.entries.remove(&id);
                Ok(())
            }
            None => Err(Refusal::Above {
                dimension,
                bound: bound as u64,
            }),
        }
    }
}

/// Checks a key (karyos#736): a stream's is a wire stream id (`i32`, decimal), any
/// other's a label of 1 to [`MAX_KEY_BYTES`] bytes without space or
/// control characters.
pub(crate) fn check_key(kind: Kind, key: &str) -> Result<(), Refusal> {
    if key.len() > MAX_KEY_BYTES {
        return Err(Refusal::Above {
            dimension: "join.key_bytes",
            bound: MAX_KEY_BYTES as u64,
        });
    }
    let fine = match kind {
        Kind::Stream => key.parse::<i32>().is_ok_and(|id| id.to_string() == key),
        Kind::Point | Kind::Counter => {
            !key.is_empty() && key.bytes().all(|byte| byte > b' ' && byte != 0x7f)
        }
    };
    if fine {
        Ok(())
    } else {
        Err(Refusal::Bad("key"))
    }
}

/// Checks `attributes`, `name=value` separated by single spaces, and
/// answers them as kept.
fn check_attributes(attributes: &str) -> Result<String, Refusal> {
    let mut names: Vec<&str> = Vec::with_capacity(MAX_ATTRIBUTES);
    for attribute in attributes.split(' ') {
        let (name, value) = attribute.split_once('=').ok_or(Refusal::Bad("attribute"))?;
        if names.len() == MAX_ATTRIBUTES {
            return Err(Refusal::Above {
                dimension: "join.attributes_per_entry",
                bound: MAX_ATTRIBUTES as u64,
            });
        }
        if name.len() > MAX_NAME_BYTES {
            return Err(Refusal::Above {
                dimension: "join.name_bytes",
                bound: MAX_NAME_BYTES as u64,
            });
        }
        if value.len() > MAX_VALUE_BYTES {
            return Err(Refusal::Above {
                dimension: "join.value_bytes",
                bound: MAX_VALUE_BYTES as u64,
            });
        }
        let name_fine = !name.is_empty()
            && name.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.".contains(&byte)
            });
        let value_fine = !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'=');
        if !name_fine {
            return Err(Refusal::Bad("attribute name"));
        }
        if !value_fine {
            return Err(Refusal::Bad("attribute value"));
        }
        if names.contains(&name) {
            return Err(Refusal::Bad("attribute repeated"));
        }
        names.push(name);
    }
    Ok(attributes.to_owned())
}

#[cfg(test)]
mod tests;
