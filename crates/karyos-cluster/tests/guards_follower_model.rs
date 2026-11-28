// SPDX-License-Identifier: Apache-2.0

//! The safety model of replicated guards' delivery to drivers
//! (quantstratum-docs: karyos/design/replicated-guards-delivery.md, §8;
//! C9 part b, karyos#683), extending part (a)'s model
//! (`guards_model.rs`) with the driver side that note decides: the
//! follower, its lease latch on driver time, the recovery token, the
//! provenance of an open, snapshot reconciliation and the local word
//! whose epoch is the senders' inhibit generation.
//!
//! One guard, **the real replicated table**
//! ([`karyos_cluster::guards::GuardTable`]), one follower and its local
//! word, one sender, explored exhaustively over bounded interleavings of
//! closes, reopens (current and stale), renewals (timely and late),
//! time passing with no entry (driver time ahead of a stalled log), a
//! clock fault, the follower's separate steps (expiry detection, one
//! effect, a snapshot install that replaces the image and discards the
//! queue, the proposal of its recovery close), and a sender that checks
//! its gate, stalls, acknowledges and exposes as separate steps, with the
//! driver's clock anywhere in `[-δ, δ]` of the reference clock.
//!
//! The invariants are judged from records the follower does not keep
//! itself (the table's history, the token closes the table applied, the
//! grants), so a flawed follower is caught, not trusted:
//!
//! - **I1** no exposure after a close is effective for the sender, until
//!   a reopen of that close's fence: both predicates, the reduced epoch
//!   form and fence provenance, per exposure;
//! - **I2** a sender that acknowledged the latch's local close exposes
//!   nothing while latched;
//! - **I3** every lapse reaches the driver closed before the grant that
//!   ends it;
//! - **I4** a reopen applies only while the lease is active;
//! - **I5** a latch lifts only after this loss's token close, then a
//!   reopen at or above its fence;
//! - **I6** bounded loss: an exposure by a sender that acknowledged every
//!   local close falls within a grant, issued at or before it and not yet
//!   ended, on the reference clock;
//! - **I7** every latch leaves the local word closed;
//! - **I8** no grant raises the deadline over an expiry the follower has
//!   not recorded (a loss is never overwritten unreported).

#![allow(clippy::unwrap_used, clippy::panic, missing_docs)]

use std::collections::HashSet;

use karyos_cluster::guards::{
    GuardBounds, GuardEffect, GuardEntry, GuardOutcome, GuardTable, Lease as TableLease, Profile,
};

/// The modelled guard's id.
const GUARD: u64 = 1;
/// The lease's lifetime, in ticks.
const LIFETIME: u64 = 4;
/// The declared skew `δ`, in ticks.
const DELTA: u64 = 1;
/// The follower's action bound `ε`, in ticks: detection is due within it.
const EPSILON: u64 = 1;
/// Snapshot installs a run takes at most: each one while latched mints
/// a fresh token, so they are bounded as entries are.
const INSTALLS: u8 = 2;
/// The reason of a driver's recovery close.
const DRIVER_LOSS: u32 = 7;
/// The top bit marks a recovery token (design §3).
const TOKEN_BIT: u64 = 1 << 63;

#[derive(Debug, Clone, Copy)]
struct Bounds {
    time: u64,
    entries: u8,
}

/// `KARYOS_GUARD_MODEL_BOUNDS=time,entries` overrides the bounds.
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
        // 6 ticks and 4 entries take about 3 minutes unoptimised (the
        // gate's `cargo test`), half a minute optimised; 7 and 5, about
        // 17 minutes optimised, were run clean at the design's commit.
        .unwrap_or(SMALL)
}

const SMALL: Bounds = Bounds {
    time: 6,
    entries: 4,
};

/// The flawed rules, each switchable; each must be caught.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Flaw {
    None,
    /// The latch lifts on any provenanced reopen after the loss, without
    /// this loss's token close.
    LiftWithoutToken,
    /// A grant extends the deadline before the expiry is detected.
    ExtendBeforeDetect,
    /// The latch point without the `δ` and `ε` margins.
    NoMargin,
    /// An install keeps the queue and applies opens without provenance.
    InstallKeepsQueue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Effect {
    /// The guard's state; `token` when the close carries a recovery token.
    Guard {
        fence: u64,
        open: bool,
        token: Option<u64>,
    },
    /// A grant (model time), and whether it ends a lapse.
    Lease { until: u64, after_lapse: bool },
}

/// What the table applied, recorded for the invariants.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Log {
    guards: GuardTable,
    log_time: u64,
    /// Every applied state of the guard: (fence, open).
    history: Vec<(u64, bool)>,
    /// The fence of each token close applied, by token.
    token_fences: Vec<(u64, u64)>,
    /// Every grant applied: (`issued`, `until`), model time.
    grants: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Follower {
    /// Its image of the replicated guard.
    fence: u64,
    open: bool,
    /// Whether the image's open is provenanced (design §5).
    provenanced: bool,
    /// The fence of the last close it applied.
    close_fence: u64,
    deadline: Option<u64>,
    latched: bool,
    /// The current loss's token, and its recovery fence once applied.
    token: Option<u64>,
    recovery: Option<u64>,
    losses: u64,
    delivered: usize,
    /// The local word: epoch, odd closed, even open.
    local: u64,
    /// The replicated fence each local open came from, by local epoch.
    opened_by: Vec<(u64, u64)>,
    /// The highest replicated close fence applied before each local
    /// close, by local epoch.
    closed_at: Vec<(u64, u64)>,
    /// Whether the clock fault has happened (once).
    faulted: bool,
    /// Snapshot installs taken, at most [`INSTALLS`].
    installs: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Sender {
    /// A passed check, held across a stall: the local epoch.
    checked: Option<u64>,
    applied: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct World {
    now: u64,
    entries: u8,
    next_op: u64,
    log: Log,
    effects: Vec<Effect>,
    follower: Follower,
    sender: Sender,
    skew: i64,
}

impl World {
    fn new(skew: i64) -> Self {
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
        Self {
            now: 0,
            entries: 0,
            next_op: 1,
            log: Log {
                guards,
                log_time: 1,
                history: vec![(1, false)],
                token_fences: Vec::new(),
                grants: Vec::new(),
            },
            effects: Vec::new(),
            follower: Follower {
                fence: 1,
                open: false,
                provenanced: false,
                close_fence: 1,
                deadline: None,
                // A starting driver is latched (design §6).
                latched: true,
                token: Some(TOKEN_BIT | 1),
                recovery: None,
                losses: 1,
                delivered: 0,
                local: 1,
                opened_by: Vec::new(),
                closed_at: Vec::new(),
                faulted: false,
                installs: 0,
            },
            sender: Sender {
                checked: None,
                applied: 1,
            },
            skew,
        }
    }

    fn clock(&self) -> u64 {
        self.now.saturating_add_signed(self.skew)
    }

    fn margin(flaw: Flaw) -> u64 {
        if flaw == Flaw::NoMargin {
            0
        } else {
            DELTA + EPSILON
        }
    }

    /// Whether the follower's clock is at or past its latch point.
    fn due(&self, flaw: Flaw) -> bool {
        let f = &self.follower;
        !f.latched
            && f.deadline
                .is_some_and(|until| self.clock() >= until.saturating_sub(Self::margin(flaw)))
    }

    fn lease_live(&self, flaw: Flaw) -> bool {
        self.follower
            .deadline
            .is_some_and(|until| self.clock() < until.saturating_sub(Self::margin(flaw)))
    }

    /// Applies one entry through the real table and queues its effects.
    fn apply(&mut self, entry: GuardEntry, event: u64) -> Result<(), String> {
        self.entries += 1;
        let index = u64::from(self.entries) + 2;
        let log_time = self.log.log_time.max(event + 1);
        self.log.log_time = log_time;
        let active =
            matches!(self.log.guards.lease(), TableLease::Active { until, .. } if log_time < until);
        let lapsed_before = matches!(self.log.guards.lease(), TableLease::Lapsed { .. });
        let reopen = matches!(entry, GuardEntry::Reopen { .. });
        let outcome = self
            .log
            .guards
            .apply(entry, index, log_time)
            .map_err(|stop| format!("stop: {stop}"))?;
        if reopen && outcome == GuardOutcome::Accepted && !active {
            return Err("I4: a reopen applied without an active lease".into());
        }
        let effects: Vec<GuardEffect> = self.log.guards.effects().to_vec();
        let lapsed_here = effects.iter().any(|effect| {
            matches!(
                effect,
                GuardEffect::Lease {
                    lease: TableLease::Lapsed { .. },
                    ..
                }
            )
        });
        for effect in effects {
            match effect {
                GuardEffect::Guard { guard, .. } => {
                    self.log.history.push((guard.fence, guard.open()));
                    let token = (!guard.open()
                        && guard.last.reason == DRIVER_LOSS
                        && guard.last.operation & TOKEN_BIT != 0)
                        .then_some(guard.last.operation);
                    if let Some(token) = token {
                        self.log.token_fences.push((token, guard.fence));
                    }
                    self.effects.push(Effect::Guard {
                        fence: guard.fence,
                        open: guard.open(),
                        token,
                    });
                }
                GuardEffect::Lease {
                    lease: TableLease::Active { issued, until },
                    ..
                } => {
                    self.log.grants.push((issued - 1, until - 1));
                    self.effects.push(Effect::Lease {
                        until: until - 1,
                        after_lapse: lapsed_before || lapsed_here,
                    });
                }
                _ => {}
            }
        }
        if matches!(self.log.guards.lease(), TableLease::Lapsed { .. })
            && self.log.guards.guard(GUARD).unwrap().open()
        {
            return Err("I3: a lapse left the guard open in the table".into());
        }
        Ok(())
    }

    /// The highest replicated close fence the follower has applied.
    fn applied_close_fence(&self) -> u64 {
        self.follower.close_fence
    }

    /// The rule of design §1, applied to the local word.
    fn reconcile(&mut self, flaw: Flaw) -> Result<(), String> {
        // The latch lifts on this loss's token close, then a reopen at or
        // above its fence.
        let lift = {
            let f = &self.follower;
            f.latched
                && f.open
                && f.provenanced
                && self.lease_live(flaw)
                && match flaw {
                    Flaw::LiftWithoutToken => true,
                    _ => f.recovery.is_some_and(|fence| f.fence >= fence),
                }
        };
        if lift {
            // I5, from the table's record, not the follower's.
            let token = self.follower.token;
            let ok = token.is_some_and(|token| {
                self.log
                    .token_fences
                    .iter()
                    .any(|&(t, fence)| t == token && self.follower.fence >= fence)
            });
            if !ok {
                return Err(format!(
                    "I5: the latch lifted at fence {} without this loss's token close",
                    self.follower.fence
                ));
            }
            self.follower.latched = false;
            self.follower.token = None;
            self.follower.recovery = None;
        }
        let f = &self.follower;
        let want = f.open && f.provenanced && !f.latched && self.lease_live(flaw);
        let is_open = f.local.is_multiple_of(2);
        if want && !is_open {
            let fence = f.fence;
            self.follower.local += 1;
            let local = self.follower.local;
            self.follower.opened_by.push((local, fence));
        } else if !want && is_open {
            let fence = self.applied_close_fence();
            self.follower.local += 1;
            let local = self.follower.local;
            self.follower.closed_at.push((local, fence));
        }
        Ok(())
    }

    /// Expiry detection, or a clock fault: latch, mint a token.
    fn latch(&mut self, flaw: Flaw) -> Result<(), String> {
        let f = &mut self.follower;
        f.latched = true;
        f.losses += 1;
        f.token = Some(TOKEN_BIT | f.losses);
        f.recovery = None;
        self.reconcile(flaw)?;
        // I7: a latch leaves the local word closed.
        if self.follower.local.is_multiple_of(2) {
            return Err("I7: a latch left the local word open".into());
        }
        Ok(())
    }

    fn detect(&mut self, flaw: Flaw) -> Result<(), String> {
        if self.due(flaw) {
            self.latch(flaw)?;
        }
        Ok(())
    }

    fn deliver(&mut self, flaw: Flaw) -> Result<(), String> {
        let Some(effect) = self.effects.get(self.follower.delivered).copied() else {
            return Ok(());
        };
        self.follower.delivered += 1;
        match effect {
            Effect::Guard { fence, open, token } => {
                let f = &mut self.follower;
                if open {
                    // Provenance (§5): the reopen of the fence of the last
                    // close applied.
                    f.provenanced = flaw == Flaw::InstallKeepsQueue || fence == f.close_fence;
                } else {
                    f.close_fence = fence;
                    f.provenanced = false;
                    if token.is_some() && token == f.token {
                        f.recovery = Some(fence);
                    }
                }
                f.fence = fence;
                f.open = open;
            }
            Effect::Lease { until, after_lapse } => {
                if after_lapse && self.follower.open {
                    return Err("I3: a grant after a lapse reached a driver still open".into());
                }
                // Detection before extension (§2).
                if flaw != Flaw::ExtendBeforeDetect {
                    self.detect(flaw)?;
                }
                // I8: no deadline is raised over an expiry the follower has
                // not recorded.
                if self.due(flaw) {
                    return Err("I8: a grant raised the deadline over an unrecorded expiry".into());
                }
                let f = &mut self.follower;
                f.deadline = Some(f.deadline.map_or(until, |old| old.max(until)));
            }
        }
        self.reconcile(flaw)
    }

    /// A snapshot install (§6): close, discard the queue, replace the
    /// image, keep the latch with a fresh token.
    fn install(&mut self, flaw: Flaw) -> Result<(), String> {
        let f = &mut self.follower;
        // Inhibit through the install: the local word closes first.
        if f.local.is_multiple_of(2) {
            f.local += 1;
            let local = f.local;
            let fence = f.close_fence;
            f.closed_at.push((local, fence));
        }
        if flaw != Flaw::InstallKeepsQueue {
            f.delivered = self.effects.len();
        }
        let g = self.log.guards.guard(GUARD).unwrap();
        f.fence = g.fence;
        f.open = g.open();
        // The installed fence is the last close's, or the reopen of it.
        f.close_fence = g.fence;
        f.provenanced = g.open();
        f.deadline = match self.log.guards.lease() {
            TableLease::Active { until, .. } => Some(until - 1),
            _ => f.deadline,
        };
        if f.latched {
            // Recovery evidence is not carried: a fresh token.
            f.losses += 1;
            f.token = Some(TOKEN_BIT | f.losses);
            f.recovery = None;
        }
        self.reconcile(flaw)
    }

    fn expose(&mut self) -> Result<(), String> {
        let Some(epoch) = self.sender.checked.take() else {
            return Ok(());
        };
        let applied = self.sender.applied;
        // I1, reduced: a close the sender acknowledged after its check.
        if applied > epoch {
            return Err(format!(
                "I1: exposure at local epoch {epoch} after the sender applied {applied}"
            ));
        }
        // I1, fence provenance: the open it exposes under must be a reopen
        // of a fence at least every replicated close the sender
        // acknowledged.
        let acked_close = self
            .follower
            .closed_at
            .iter()
            .filter(|&&(local, _)| local <= applied)
            .map(|&(_, fence)| fence)
            .max()
            .unwrap_or(0);
        let opened = self
            .follower
            .opened_by
            .iter()
            .find(|&&(local, _)| local == epoch)
            .map(|&(_, fence)| fence)
            .unwrap_or(0);
        if opened < acked_close {
            return Err(format!(
                "I1: exposure under an open of fence {opened} after a close of fence {acked_close} was effective"
            ));
        }
        // I2: latched, and the sender acknowledged the local close.
        if self.follower.latched && applied == self.follower.local && !applied.is_multiple_of(2) {
            return Err("I2: a sender that acknowledged the latch exposed".into());
        }
        // I6: on the reference clock, an exposure by a sender that
        // acknowledged every local close is covered by a grant: one issued
        // at or before it whose lease has not ended.
        let covered = self
            .log
            .grants
            .iter()
            .any(|&(issued, until)| issued <= self.now && self.now < until);
        if !covered && applied == self.follower.local {
            return Err(format!(
                "I6: exposure at {} covered by no grant ({:?}) by a sender that acknowledged every close",
                self.now, self.log.grants
            ));
        }
        Ok(())
    }
}

fn successors(world: &World, flaw: Flaw, bounds: Bounds) -> Vec<(String, Result<World, String>)> {
    let mut next = Vec::new();
    let mut push = |name: String, step: &dyn Fn(&mut World) -> Result<(), String>| {
        let mut w = world.clone();
        let result = step(&mut w).map(|()| w);
        next.push((name, result));
    };
    let fence = world.log.guards.guard(GUARD).unwrap().fence;
    if world.entries < bounds.entries {
        let op = world.next_op;
        push(format!("close op{op}"), &|w| {
            w.next_op += 1;
            w.apply(
                GuardEntry::Close {
                    guard: GUARD,
                    operation: op,
                    requester: 1,
                    reason: 1,
                },
                w.now,
            )
        });
        for named in [fence, fence.saturating_sub(1).max(1)] {
            push(format!("reopen fence{named} op{op}"), &|w| {
                w.next_op += 1;
                w.apply(
                    GuardEntry::Reopen {
                        guard: GUARD,
                        fence: named,
                        operation: op,
                        requester: 1,
                        reason: 1,
                    },
                    w.now,
                )
            });
        }
        for delay in [0, 2] {
            if world.now >= delay {
                push(format!("renew issued now-{delay}"), &|w| {
                    let issued = w.now - delay;
                    w.apply(GuardEntry::Renew { issued: issued + 1 }, issued)
                });
            }
        }
        // The follower's recovery close, while latched and not applied.
        if let Some(token) = world.follower.token
            && world.follower.latched
            && !world.log.token_fences.iter().any(|&(t, _)| t == token)
        {
            push(format!("recovery close {token:#x}"), &|w| {
                w.apply(
                    GuardEntry::Close {
                        guard: GUARD,
                        operation: token,
                        requester: 9,
                        reason: DRIVER_LOSS,
                    },
                    w.now,
                )
            });
        }
    }
    // Time passes with no entry, but never past a due detection by more
    // than ε: the follower acts within ε (design §2).
    if world.now < bounds.time && !world.due(flaw) {
        push("tick".into(), &|w| {
            w.now += 1;
            Ok(())
        });
    }
    if world.due(flaw) {
        push("detect expiry".into(), &|w| w.detect(flaw));
    }
    if !world.follower.faulted {
        push("clock fault".into(), &|w| {
            w.follower.faulted = true;
            w.latch(flaw)
        });
    }
    if world.follower.delivered < world.effects.len() {
        push("deliver".into(), &|w| w.deliver(flaw));
    }
    if world.follower.installs < INSTALLS {
        push("install snapshot".into(), &|w| {
            w.follower.installs += 1;
            w.install(flaw)
        });
    }
    if world.sender.checked.is_none() {
        if world.follower.local.is_multiple_of(2) {
            push("sender checks".into(), &|w| {
                w.sender.checked = Some(w.follower.local);
                Ok(())
            });
        }
        if world.sender.applied != world.follower.local {
            push("sender acknowledges".into(), &|w| {
                w.sender.applied = w.follower.local;
                Ok(())
            });
        }
    } else {
        push("sender exposes".into(), &|w| w.expose());
    }
    next
}

/// [`search_on`] on a thread whose stack holds the depth-first search.
fn search(flaw: Flaw, bounds: Bounds) -> Option<(String, Vec<String>)> {
    std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(move || search_on(flaw, bounds))
        .unwrap()
        .join()
        .unwrap()
}

fn search_on(flaw: Flaw, bounds: Bounds) -> Option<(String, Vec<String>)> {
    let delta = i64::try_from(DELTA).unwrap();
    (-delta..=delta).find_map(|skew| {
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
        visit(World::new(skew), flaw, bounds, &mut HashSet::new())
    })
}

#[test]
fn the_delivery_design_keeps_every_invariant_with_skew() {
    let found = search(Flaw::None, bounds());
    assert_eq!(found, None, "{found:?}");
}

#[test]
fn each_flawed_rule_is_caught() {
    // A kept queue replays stale effects over the installed image: the
    // first one the search reaches is a stale open (I1) or a stale grant
    // after a lapse (I3), whichever its depth-first order meets first.
    for (flaw, invariants) in [
        (Flaw::LiftWithoutToken, &["I5"][..]),
        (Flaw::ExtendBeforeDetect, &["I8"][..]),
        (Flaw::NoMargin, &["I6"][..]),
        (Flaw::InstallKeepsQueue, &["I1", "I3"][..]),
    ] {
        let found = search(flaw, bounds());
        assert!(
            found.as_ref().is_some_and(|(violation, _)| invariants
                .iter()
                .any(|invariant| violation.starts_with(invariant))),
            "{flaw:?} not caught as {invariants:?} within {:?}: {found:?}",
            bounds()
        );
    }
}
