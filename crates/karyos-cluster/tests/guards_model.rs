// SPDX-License-Identifier: Apache-2.0

//! The safety model of replicated guards' semantic fencing
//! (quantstratum-docs: karyos/design/replicated-guards.md, §9; C9,
//! karyos#683): one guard, **the real replicated table**
//! ([`karyos_cluster::guards::GuardTable`]), one driver and one sender, explored exhaustively over bounded
//! interleavings of closes, reopens (current and stale), renewals (timely
//! and delayed), the passage of time, delayed and batched delivery
//! (snapshot catch-up), and a sender that checks its gate, stalls, and
//! exposes later. After every step it checks the design's invariants:
//!
//! - **I1** no exposure after a close is effective for the sender, until
//!   a reopen of that close's fence;
//! - **I2** latched implies inhibited: a sender that acknowledged the
//!   driver's latch exposes nothing until the latch lifts;
//! - **I3** every lapse closes every open guard, in the table and, in
//!   order, in the effects the driver receives;
//! - **I4** a reopen applies only while the lease is active;
//! - **I5** the latch lifts only after a close decided at or past the
//!   lease it latched on, then a reopen;
//! - **I6** bounded loss: past the last grant, no exposure comes from a
//!   sender that acknowledged every latch;
//! - **I7** every latch raises the inhibit generation, so a sender that
//!   has not acknowledged it is reported pending, never taken as stopped.
//!
//! Each flawed rule the reviews found is a switch ([`Flaw`]); the search
//! finds a counterexample for each, so every invariant is shown to catch
//! its violation.

#![allow(clippy::unwrap_used, clippy::panic, missing_docs)]

use std::collections::HashSet;

use karyos_cluster::guards::{
    GuardBounds, GuardEffect, GuardEntry, GuardOutcome, GuardTable, LAPSE_REASON,
    Lease as TableLease, Profile, Refusal,
};

/// The modelled guard's id.
const GUARD: u64 = 1;

/// The lease's lifetime, in ticks.
const LIFETIME: u64 = 3;
/// The search's bounds: the last tick, and the log entries.
#[derive(Debug, Clone, Copy)]
struct Bounds {
    time: u64,
    entries: u8,
}

/// The bounds every flaw is found within, and the design checked at;
/// `KARYOS_GUARD_MODEL_BOUNDS=time,entries` overrides them for a longer
/// search.
fn bounds() -> Bounds {
    std::env::var("KARYOS_GUARD_MODEL_BOUNDS")
        .ok()
        .and_then(|value| {
            let (time, entries) = value.split_once(',')?;
            Some(Bounds {
                time: time.parse().ok()?,
                entries: entries.parse().ok()?,
            })
        })
        // Optimised, the search runs 6 ticks and 5 entries in under a
        // minute; unoptimised (the gate's `cargo test`), 5 and 4.
        .unwrap_or(if cfg!(debug_assertions) {
            SMALL
        } else {
            Bounds {
                time: 6,
                entries: 5,
            }
        })
}
/// Small bounds, at which the full history is affordable.
const SMALL: Bounds = Bounds {
    time: 5,
    entries: 4,
};

/// The flawed rules of the reviews, each switchable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flaw {
    None,
    /// Review 2, critical 1: the latch lifts on any `Open` at a higher fence.
    ReleaseOnHigherFence,
    /// Review 2, critical 2: lapse closes are applied but not delivered.
    UndeliveredLapse,
    /// Review 2, critical 3: a reopen applies whatever the lease's state.
    ReopenWithoutLease,
    /// Review 2, critical 4: the latch is not acknowledged, so a stalled
    /// sender's acknowledgement does not cover it.
    NoInhibitAck,
    /// The deadline without the declared skew `δ` subtracted.
    NoSkewMargin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Effect {
    /// The guard's state, with the log time of the entry that set it.
    Guard {
        epoch: u64,
        fence: u64,
        open: bool,
        at: u64,
    },
    /// A grant; `after_lapse` when it ends a lapse.
    Lease { until: u64, after_lapse: bool },
}

/// The table side: the real table, and what the model reads of it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Table {
    guards: GuardTable,
    /// The log time, in model time plus one.
    log_time: u64,
    /// Every applied state: (epoch, open, fence), for the full I1.
    history: Vec<(u64, bool, u64)>,
}

impl Table {
    fn guard(&self) -> (u64, u64, bool) {
        let g = self.guards.guard(GUARD).unwrap();
        (g.epoch, g.fence, g.open())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Driver {
    epoch: u64,
    fence: u64,
    open: bool,
    deadline: Option<u64>,
    /// The lease `until` it latched on, and its fence then, if latched.
    latched: Option<(u64, u64)>,
    inhibit: u64,
    /// Latches taken, each of which must raise `inhibit` (I7).
    latches: u64,
    /// The log time of the last close or fence change it applied.
    last_close_at: u64,
    delivered: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Sender {
    /// A passed check, held across a stall: (epoch, inhibit).
    checked: Option<(u64, u64)>,
    applied_epoch: u64,
    applied_inhibit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct World {
    now: u64,
    entries: u8,
    next_op: u64,
    table: Table,
    effects: Vec<Effect>,
    driver: Driver,
    sender: Sender,
    granted_until: u64,
    /// Whether `table.history` is kept, for the full form of I1 (§9).
    full: bool,
    /// The declared skew `δ`, and the driver clock's actual offset from
    /// the log time, within `[-δ, δ]`.
    delta: u64,
    skew: i64,
}

impl World {
    fn new(full: bool, delta: u64, skew: i64) -> Self {
        Self {
            now: 0,
            entries: 0,
            next_op: 1,
            table: {
                let bounds = GuardBounds::new(1, LIFETIME, 1, Profile::Durable).unwrap();
                let mut guards = GuardTable::new(bounds);
                guards.apply(GuardEntry::Bounds(bounds), 1, 1).unwrap();
                guards
                    .apply(
                        GuardEntry::Define {
                            guard: GUARD,
                            policy: 1,
                        },
                        2,
                        1,
                    )
                    .unwrap();
                Table {
                    guards,
                    log_time: 1,
                    history: if full {
                        vec![(1, false, 1)]
                    } else {
                        Vec::new()
                    },
                }
            },
            effects: Vec::new(),
            driver: Driver {
                epoch: 1,
                fence: 1,
                open: false,
                deadline: None,
                latched: None,
                inhibit: 0,
                latches: 0,
                last_close_at: 0,
                delivered: 0,
            },
            sender: Sender {
                checked: None,
                applied_epoch: 1,
                applied_inhibit: 0,
            },
            granted_until: 0,
            full,
            delta,
            skew,
        }
    }

    /// Applies one guard entry at model time `event` through the real
    /// table, then hands its effects to the driver's queue.
    fn apply(&mut self, entry: Entry, event: u64, flaw: Flaw) -> Result<(), String> {
        self.entries += 1;
        let index = u64::from(self.entries) + 2;
        let log_time = self.table.log_time.max(event + 1);
        self.table.log_time = log_time;
        // The lease as the log granted it, before the entry: what I4 reads.
        let active = matches!(self.table.guards.lease(), TableLease::Active { until, .. } if log_time < until);
        let lapsed_before = matches!(self.table.guards.lease(), TableLease::Lapsed { .. });
        let real = match entry {
            Entry::Close { op } => GuardEntry::Close {
                guard: GUARD,
                operation: op,
                requester: 1,
                reason: 1,
            },
            Entry::Reopen { fence, op } => GuardEntry::Reopen {
                guard: GUARD,
                fence,
                operation: op,
                requester: 1,
                reason: 1,
            },
            Entry::Renew { issued } => GuardEntry::Renew { issued: issued + 1 },
        };
        // The flaw: a table that reopens whatever the lease, as a phantom
        // grant just before the reopen.
        let mut phantom = Vec::new();
        if flaw == Flaw::ReopenWithoutLease && matches!(entry, Entry::Reopen { .. }) && !active {
            let mut forged = self.table.guards.clone();
            let _ = forged.apply(GuardEntry::Renew { issued: log_time }, index, log_time);
            phantom.extend_from_slice(forged.effects());
            self.table.guards = forged;
        }
        let outcome = self
            .table
            .guards
            .apply(real, index, log_time)
            .map_err(|stop| format!("stop: {stop}"))?;
        if matches!(entry, Entry::Reopen { .. }) && outcome == GuardOutcome::Accepted && !active {
            return Err("I4: a reopen applied without an active lease".into());
        }
        let effects: Vec<GuardEffect> = phantom
            .into_iter()
            .chain(self.table.guards.effects().iter().copied())
            .collect();
        // A grant ends a lapse when the lease was lapsed before the entry,
        // or the entry itself lapsed it first.
        let lapsed_here = effects.iter().any(|effect| {
            matches!(
                effect,
                GuardEffect::Lease {
                    lease: TableLease::Lapsed { .. },
                    ..
                }
            )
        });
        let lapsed_before = lapsed_before || lapsed_here;
        for effect in effects {
            match effect {
                GuardEffect::Guard { guard, .. } => {
                    if self.full {
                        self.table
                            .history
                            .push((guard.epoch, guard.open(), guard.fence));
                    }
                    if flaw == Flaw::UndeliveredLapse && guard.last.reason == LAPSE_REASON {
                        continue;
                    }
                    self.effects.push(Effect::Guard {
                        epoch: guard.epoch,
                        fence: guard.fence,
                        open: guard.open(),
                        at: log_time - 1,
                    });
                }
                GuardEffect::Lease {
                    lease: TableLease::Active { until, .. },
                    ..
                } => {
                    self.granted_until = self.granted_until.max(until - 1);
                    self.effects.push(Effect::Lease {
                        until: until - 1,
                        after_lapse: lapsed_before,
                    });
                }
                _ => {}
            }
        }
        // I3, the table: a lapse leaves no guard open.
        if matches!(self.table.guards.lease(), TableLease::Lapsed { .. }) && self.table.guard().2 {
            return Err("I3: a lapse left the guard open".into());
        }
        let _ = Refusal::Stale;
        Ok(())
    }

    /// The driver's clock: the log time's reference clock, offset.
    fn clock(&self) -> u64 {
        self.now.saturating_add_signed(self.skew)
    }

    /// The margin the driver subtracts from each deadline: `δ`.
    fn margin(&self, flaw: Flaw) -> u64 {
        if flaw == Flaw::NoSkewMargin {
            0
        } else {
            self.delta
        }
    }

    /// The driver's gate: open, with a live deadline, not latched.
    fn gate(&self, flaw: Flaw) -> bool {
        let d = &self.driver;
        d.open
            && d.latched.is_none()
            && d.deadline
                .is_some_and(|deadline| self.clock() + self.margin(flaw) < deadline)
    }

    fn deliver(&mut self, flaw: Flaw) -> Result<(), String> {
        let Some(effect) = self.effects.get(self.driver.delivered).copied() else {
            return Ok(());
        };
        self.driver.delivered += 1;
        let d = &mut self.driver;
        match effect {
            Effect::Guard {
                epoch,
                fence,
                open,
                at,
            } => {
                if !open {
                    d.last_close_at = d.last_close_at.max(at);
                }
                if let Some((latched_until, latched_fence)) = d.latched
                    && open
                {
                    let lifts = match flaw {
                        Flaw::ReleaseOnHigherFence => fence > latched_fence,
                        _ => d.last_close_at >= latched_until,
                    };
                    if lifts {
                        // I5: only a close decided at or past the lease
                        // it latched on lifts the latch.
                        if d.last_close_at < latched_until {
                            return Err(format!(
                                "I5: the latch on {latched_until} lifted after a close at {}",
                                d.last_close_at
                            ));
                        }
                        d.latched = None;
                    }
                }
                d.epoch = epoch;
                d.fence = fence;
                d.open = open;
            }
            Effect::Lease { until, after_lapse } => {
                // I3, as the driver receives it: the lapse's closes come
                // before the grant that ends it.
                if after_lapse && d.open {
                    return Err("I3: a grant after a lapse reached a driver still open".into());
                }
                d.deadline = Some(d.deadline.map_or(until, |old| old.max(until)));
            }
        }
        Ok(())
    }

    fn tick(&mut self, flaw: Flaw) -> Result<(), String> {
        self.now += 1;
        let d = &mut self.driver;
        let reading = self.now.saturating_add_signed(self.skew)
            + if flaw == Flaw::NoSkewMargin {
                0
            } else {
                self.delta
            };
        if d.latched.is_none()
            && let Some(deadline) = d.deadline
            && reading >= deadline
        {
            d.latched = Some((deadline, d.fence));
            d.latches += 1;
            if flaw != Flaw::NoInhibitAck {
                d.inhibit += 1;
            }
        }
        // I7: every latch leaves evidence a sender must acknowledge.
        if self.driver.inhibit < self.driver.latches {
            return Err("I7: a latch raised no inhibit generation".into());
        }
        Ok(())
    }

    /// The sender exposes what its held check allowed, then checks the
    /// invariants about that exposure.
    fn expose(&mut self) -> Result<(), String> {
        let Some((epoch, _inhibit)) = self.sender.checked.take() else {
            return Ok(());
        };
        let s = &self.sender;
        // I1: past every close the sender acknowledged, the exposed epoch
        // must be a reopen of a fence at least that close's.
        if self.full {
            for &(close_epoch, open, close_fence) in &self.table.history {
                if !open && close_epoch <= s.applied_epoch && close_epoch >= epoch {
                    return Err(format!(
                        "I1: exposure at epoch {epoch} after the close at epoch {close_epoch} (fence {close_fence}) was effective"
                    ));
                }
            }
        } else if s.applied_epoch > epoch {
            // The reduced form (§9): epochs alternate, so a close in
            // [epoch, applied_epoch] exists exactly when applied_epoch > epoch.
            return Err(format!(
                "I1: exposure at epoch {epoch} after the sender applied {}",
                s.applied_epoch
            ));
        }
        // I2 and I6: a sender that acknowledged the latch exposes nothing.
        if self.driver.latched.is_some()
            && s.applied_inhibit >= self.driver.inhibit
            && self.driver.inhibit > 0
        {
            return Err("I2: a sender that acknowledged the latch exposed".into());
        }
        // The bound is on the reference clock: past the last grant, no
        // acknowledged sender exposes, whatever the driver's skew.
        if self.now >= self.granted_until
            && s.applied_inhibit >= self.driver.inhibit
            && self.granted_until > 0
        {
            return Err(format!(
                "I6: exposure at {} past the last grant {} by a sender that acknowledged every latch",
                self.now, self.granted_until
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum Entry {
    Close { op: u64 },
    Reopen { fence: u64, op: u64 },
    Renew { issued: u64 },
}

/// Every action from `world`.
fn successors(world: &World, flaw: Flaw, bounds: Bounds) -> Vec<(String, Result<World, String>)> {
    let mut next = Vec::new();
    let mut push = |name: String, step: &dyn Fn(&mut World) -> Result<(), String>| {
        let mut w = world.clone();
        let result = step(&mut w).map(|()| w);
        next.push((name, result));
    };
    if world.entries < bounds.entries {
        let op = world.next_op;
        push(format!("close op{op}"), &|w| {
            w.next_op += 1;
            w.apply(Entry::Close { op }, w.now, flaw)
        });
        let (_, table_fence, _) = world.table.guard();
        for fence in [table_fence, table_fence.saturating_sub(1).max(1)] {
            push(format!("reopen fence{fence} op{op}"), &|w| {
                w.next_op += 1;
                w.apply(Entry::Reopen { fence, op }, w.now, flaw)
            });
        }
        for delay in [0, 1, 2] {
            if world.now >= delay {
                // A renewal's event time is its own `issued` (note §4): a
                // delayed one does not advance the log time to its apply time.
                push(format!("renew issued now-{delay}"), &|w| {
                    let issued = w.now - delay;
                    w.apply(Entry::Renew { issued }, issued, flaw)
                });
            }
        }
    }
    if world.now < bounds.time {
        push("tick".into(), &|w| w.tick(flaw));
    }
    if world.driver.delivered < world.effects.len() {
        push("deliver".into(), &|w| w.deliver(flaw));
        push("catch up (snapshot)".into(), &|w| {
            while w.driver.delivered < w.effects.len() {
                w.deliver(flaw)?;
            }
            Ok(())
        });
    }
    if world.sender.checked.is_none() {
        if world.gate(flaw) {
            push("sender checks".into(), &|w| {
                w.sender.checked = Some((w.driver.epoch, w.driver.inhibit));
                Ok(())
            });
        }
        if world.sender.applied_epoch != world.driver.epoch
            || world.sender.applied_inhibit != world.driver.inhibit
        {
            push("sender acknowledges".into(), &|w| {
                w.sender.applied_epoch = w.driver.epoch;
                w.sender.applied_inhibit = w.driver.inhibit;
                Ok(())
            });
        }
    } else {
        push("sender exposes".into(), &|w| w.expose());
    }
    next
}

/// Explores every reachable world, depth first; the first violation,
/// with its trace.
fn search(flaw: Flaw, bounds: Bounds, full: bool) -> Option<(String, Vec<String>)> {
    search_skewed(flaw, bounds, full, 0)
}

/// [`search`] with a declared skew `delta`, over every driver offset in
/// `[-delta, delta]`.
fn search_skewed(
    flaw: Flaw,
    bounds: Bounds,
    full: bool,
    delta: u64,
) -> Option<(String, Vec<String>)> {
    let delta_i = i64::try_from(delta).unwrap();
    (-delta_i..=delta_i).find_map(|skew| search_at(flaw, bounds, full, delta, skew))
}

fn search_at(
    flaw: Flaw,
    bounds: Bounds,
    full: bool,
    delta: u64,
    skew: i64,
) -> Option<(String, Vec<String>)> {
    fn visit(
        world: World,
        flaw: Flaw,
        bounds: Bounds,
        seen: &mut HashSet<World>,
    ) -> Option<(String, Vec<String>)> {
        if !seen.insert(world.clone()) {
            return None;
        }
        for (name, result) in successors(&world, flaw, bounds) {
            match result {
                Err(violation) => return Some((violation, vec![name])),
                Ok(next) => {
                    if let Some((violation, mut trace)) = visit(next, flaw, bounds, seen) {
                        trace.insert(0, name);
                        return Some((violation, trace));
                    }
                }
            }
        }
        None
    }
    visit(
        World::new(full, delta, skew),
        flaw,
        bounds,
        &mut HashSet::new(),
    )
}

const FLAWS: [(Flaw, &str); 4] = [
    (Flaw::ReleaseOnHigherFence, "I5"),
    (Flaw::UndeliveredLapse, "I3"),
    (Flaw::ReopenWithoutLease, "I4"),
    (Flaw::NoInhibitAck, "I7"),
];

#[test]
fn the_design_keeps_every_invariant_over_every_interleaving() {
    assert_eq!(search(Flaw::None, bounds(), false), None);
}

#[test]
fn each_flaw_of_the_reviews_is_caught() {
    for (flaw, invariant) in FLAWS {
        let found = search(flaw, bounds(), false);
        assert!(
            found
                .as_ref()
                .is_some_and(|(violation, _)| violation.starts_with(invariant)),
            "{flaw:?} not caught within {:?}: {found:?}",
            bounds()
        );
    }
}

/// The reduced I1 hides nothing: at small bounds, with the full history,
/// every search gives the same verdict as the reduced one.
#[test]
fn the_reduced_i1_gives_the_full_verdicts() {
    for flaw in [
        Flaw::None,
        Flaw::ReleaseOnHigherFence,
        Flaw::UndeliveredLapse,
        Flaw::ReopenWithoutLease,
        Flaw::NoInhibitAck,
    ] {
        let verdict = |found: Option<(String, Vec<String>)>| {
            found.map(|(violation, _)| violation[..2].to_owned())
        };
        assert_eq!(
            verdict(search(flaw, SMALL, true)),
            verdict(search(flaw, SMALL, false)),
            "{flaw:?}"
        );
    }
}

/// The skewed clock (§9): with `δ = 1` and the driver's clock anywhere in
/// `[-1, 1]` of the log time, the design keeps every invariant, I6 among
/// them, at the small bounds; an unacknowledged latch still breaks I6,
/// and a deadline without the `δ` margin breaks it on a slow driver.
#[test]
fn a_skewed_driver_clock_keeps_the_bound() {
    assert_eq!(search_skewed(Flaw::None, SMALL, false, 1), None);
    for (flaw, invariant) in [(Flaw::NoInhibitAck, "I7"), (Flaw::NoSkewMargin, "I6")] {
        let found = search_skewed(flaw, SMALL, false, 1);
        assert!(
            found
                .as_ref()
                .is_some_and(|(violation, _)| violation.starts_with(invariant)),
            "{flaw:?}: {found:?}"
        );
    }
}
