// SPDX-License-Identifier: Apache-2.0

//! A linearizability checker over recorded histories (`quantstratum-docs:
//! karyos/design/cluster-gap-analysis.md`, C3), in house.
//!
//! A [`History`] records each client's invocations and their returns, in
//! real-time order. [`check`] decides whether some order of the
//! operations, each taking effect at one instant between its invocation
//! and its return, explains every return under a sequential [`Model`].
//!
//! - **Algorithm.** Wing and Gong's search with Lowe's memoisation: walk
//!   the history; linearize a call whose operation the model answers as
//!   recorded and remove it with its return; at a return whose call is not
//!   linearized, backtrack. A configuration (the set of operations
//!   linearized, and the model's state) is explored once.
//! - **Cost.** The worst case explores every configuration: up to `2^n`
//!   sets of `n` operations times the model's reachable states, each
//!   reached by up to `n!` orders before the memo cuts them. A concurrent
//!   history is the expensive case; a sequential one is linear. The search
//!   stops after [`Limit::max_configurations`] new configurations with
//!   [`Verdict::Undecided`], never a guess.
//! - **Pending operations.** An invocation with no return took effect or
//!   did not: it may be linearized anywhere after its invocation, with any
//!   result, or left out.
//! - **Counterexample.** For a history that is not linearizable,
//!   [`Counterexample`] is the shortest prefix, cut just after a return,
//!   that is already not linearizable, the operations still open in it
//!   being pending. Bisection finds it because non-linearizability is
//!   monotone over such prefixes: a linearization of a longer prefix,
//!   restricted to the operations of a shorter one (those still open there
//!   pending), linearizes it.

use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

#[cfg(test)]
mod tests;

/// A sequential specification: what one operation does to the state, and
/// what it returns.
pub trait Model {
    /// The state.
    type State: Clone + Eq + Hash;
    /// An operation.
    type Op: Clone + Debug;
    /// What an operation returns.
    type Ret: Clone + Eq + Debug;

    /// The initial state.
    fn init(&self) -> Self::State;

    /// `op` applied to `state`: the next state and the return.
    fn step(&self, state: &Self::State, op: &Self::Op) -> (Self::State, Self::Ret);
}

/// One event of a history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event<O, R> {
    /// `client` invoked `op`.
    Invoke {
        /// The client.
        client: u32,
        /// The operation.
        op: O,
    },
    /// `client`'s open operation returned `ret`.
    Return {
        /// The client.
        client: u32,
        /// The return.
        ret: R,
    },
}

/// A history that is not well formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryError {
    /// A return of a client with no open operation.
    ReturnWithoutInvoke {
        /// The client.
        client: u32,
    },
    /// An invocation of a client whose last operation is open.
    InvokeWhileOpen {
        /// The client.
        client: u32,
    },
}

impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReturnWithoutInvoke { client } => {
                write!(f, "client {client} returned with no operation open")
            }
            Self::InvokeWhileOpen { client } => {
                write!(f, "client {client} invoked with an operation open")
            }
        }
    }
}

impl std::error::Error for HistoryError {}

/// The events of a history, in real-time order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct History<O, R> {
    events: Vec<Event<O, R>>,
}

impl<O, R> Default for History<O, R> {
    fn default() -> Self {
        Self { events: Vec::new() }
    }
}

impl<O: Clone, R: Clone> History<O, R> {
    /// An empty history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `client` invoked `op`.
    pub fn invoke(&mut self, client: u32, op: O) -> &mut Self {
        self.events.push(Event::Invoke { client, op });
        self
    }

    /// Records that `client`'s open operation returned `ret`.
    pub fn ret(&mut self, client: u32, ret: R) -> &mut Self {
        self.events.push(Event::Return { client, ret });
        self
    }

    /// The events.
    #[must_use]
    pub fn events(&self) -> &[Event<O, R>] {
        &self.events
    }

    /// The history cut just after its `count`-th return: with 0, the
    /// invocations before its first return; with more than it has, all of
    /// it.
    fn up_to_return(&self, count: usize) -> Self {
        let mut end = self.events.len();
        let mut returns = self
            .events
            .iter()
            .enumerate()
            .filter(|(_, event)| matches!(event, Event::Return { .. }))
            .map(|(at, _)| at);
        if count == 0 {
            if let Some(first) = returns.next() {
                end = first;
            }
        } else if let Some(at) = returns.nth(count - 1) {
            // Just after the return: `at` is below the length.
            end = at.checked_add(1).unwrap_or(end);
        }
        Self {
            events: self.events.get(..end).unwrap_or_default().to_vec(),
        }
    }

    fn returns(&self) -> usize {
        self.events
            .iter()
            .filter(|event| matches!(event, Event::Return { .. }))
            .count()
    }
}

/// How far a check may search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    /// New configurations explored before the check gives up.
    pub max_configurations: u64,
}

/// A history that is not linearizable, shortened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counterexample<O, R> {
    /// The shortest prefix, cut just after a return, that is not
    /// linearizable; the operations open in it are pending.
    pub prefix: History<O, R>,
}

/// What a check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict<O, R> {
    /// An order that explains every return: the operations, numbered by
    /// invocation from 0, in the order they took effect. Pending ones left
    /// out are not in it.
    Linearizable(Vec<usize>),
    /// No order does.
    NotLinearizable(Counterexample<O, R>),
    /// The limit was reached first.
    Undecided {
        /// The configurations explored.
        explored: u64,
    },
}

/// One operation of a history.
struct Operation<O, R> {
    op: O,
    /// Its return, `None` for a pending one.
    ret: Option<R>,
}

/// One entry of the search's list: an operation's call or its return.
#[derive(Debug, Clone, Copy)]
struct Entry {
    /// The operation.
    op: usize,
    /// A call, or a return.
    call: bool,
    /// The list's links, by entry index.
    prev: Option<usize>,
    next: Option<usize>,
    /// For a call, its return entry.
    pair: Option<usize>,
}

/// The search's doubly linked list of entries, with a head.
struct List {
    entries: Vec<Entry>,
    head: Option<usize>,
}

impl List {
    fn get(&self, at: usize) -> Option<Entry> {
        self.entries.get(at).copied()
    }

    fn set_next(&mut self, at: Option<usize>, next: Option<usize>) {
        match at {
            Some(at) => {
                if let Some(entry) = self.entries.get_mut(at) {
                    entry.next = next;
                }
            }
            None => self.head = next,
        }
    }

    fn set_prev(&mut self, at: Option<usize>, prev: Option<usize>) {
        if let Some(entry) = at.and_then(|at| self.entries.get_mut(at)) {
            entry.prev = prev;
        }
    }

    /// Unlinks entry `at`; its own links stay, for [`List::relink`].
    fn unlink(&mut self, at: usize) {
        if let Some(entry) = self.get(at) {
            self.set_next(entry.prev, entry.next);
            self.set_prev(entry.next, entry.prev);
        }
    }

    /// Links entry `at` back where it was.
    fn relink(&mut self, at: usize) {
        if let Some(entry) = self.get(at) {
            self.set_next(entry.prev, Some(at));
            self.set_prev(entry.next, Some(at));
        }
    }

    /// Removes a call and its return.
    fn lift(&mut self, call: usize) {
        self.unlink(call);
        if let Some(pair) = self.get(call).and_then(|entry| entry.pair) {
            self.unlink(pair);
        }
    }

    /// Puts back what [`List::lift`] removed, in the reverse order.
    fn unlift(&mut self, call: usize) {
        if let Some(pair) = self.get(call).and_then(|entry| entry.pair) {
            self.relink(pair);
        }
        self.relink(call);
    }
}

/// A set of operations, as bits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Bits(Vec<u64>);

impl Bits {
    fn new(len: usize) -> Self {
        Self(vec![0; len.div_ceil(64)])
    }

    fn set(&mut self, at: usize, on: bool) {
        if let Some(word) = self.0.get_mut(at / 64) {
            let bit = 1u64 << (at % 64);
            if on {
                *word |= bit;
            } else {
                *word &= !bit;
            }
        }
    }
}

/// The operations of `history`, and the search's list: a call entry per
/// operation at its invocation, a return entry at its return.
fn prepare<O: Clone, R: Clone>(
    history: &History<O, R>,
) -> Result<(Vec<Operation<O, R>>, List), HistoryError> {
    let mut operations: Vec<Operation<O, R>> = Vec::new();
    let mut entries: Vec<Entry> = Vec::new();
    // Per client, its open operation's call entry.
    let mut open: Vec<(u32, usize)> = Vec::new();
    for event in &history.events {
        match event {
            Event::Invoke { client, op } => {
                if open.iter().any(|(owner, _)| owner == client) {
                    return Err(HistoryError::InvokeWhileOpen { client: *client });
                }
                open.push((*client, entries.len()));
                entries.push(Entry {
                    op: operations.len(),
                    call: true,
                    prev: None,
                    next: None,
                    pair: None,
                });
                operations.push(Operation {
                    op: op.clone(),
                    ret: None,
                });
            }
            Event::Return { client, ret } => {
                let at = open
                    .iter()
                    .position(|(owner, _)| owner == client)
                    .ok_or(HistoryError::ReturnWithoutInvoke { client: *client })?;
                let (_, call) = open.swap_remove(at);
                let returned = entries.len();
                let Some(entry) = entries.get_mut(call) else {
                    return Err(HistoryError::ReturnWithoutInvoke { client: *client });
                };
                entry.pair = Some(returned);
                let op = entry.op;
                if let Some(operation) = operations.get_mut(op) {
                    operation.ret = Some(ret.clone());
                }
                entries.push(Entry {
                    op,
                    call: false,
                    prev: None,
                    next: None,
                    pair: None,
                });
            }
        }
    }
    let count = entries.len();
    for (at, entry) in entries.iter_mut().enumerate() {
        entry.prev = at.checked_sub(1);
        entry.next = at.checked_add(1).filter(|next| *next < count);
    }
    let head = (count > 0).then_some(0);
    Ok((operations, List { entries, head }))
}

/// What the search found, before a counterexample is minimised.
enum Search {
    Order(Vec<usize>),
    No,
    Undecided(u64),
}

/// Wing and Gong's search with Lowe's memoisation over `history`.
fn search<M: Model>(
    model: &M,
    history: &History<M::Op, M::Ret>,
    limit: Limit,
) -> Result<Search, HistoryError> {
    let (operations, mut list) = prepare(history)?;
    let mut linearized = Bits::new(operations.len());
    let mut seen: HashSet<(Bits, M::State)> = HashSet::new();
    let mut state = model.init();
    // The calls linearized, with the state before each.
    let mut stack: Vec<(usize, M::State)> = Vec::new();
    let mut explored = 0u64;
    let mut cursor = list.head;
    loop {
        // Every entry left is a pending call: each may be left out.
        let Some(at) = cursor else {
            let order = stack
                .iter()
                .filter_map(|(call, _)| list.get(*call).map(|entry| entry.op))
                .collect();
            return Ok(Search::Order(order));
        };
        let Some(entry) = list.get(at) else {
            return Ok(Search::No);
        };
        if entry.call {
            let Some(operation) = operations.get(entry.op) else {
                return Ok(Search::No);
            };
            let (next, ret) = model.step(&state, &operation.op);
            let answers = operation
                .ret
                .as_ref()
                .is_none_or(|recorded| *recorded == ret);
            let mut taken = false;
            if answers {
                let mut with = linearized.clone();
                with.set(entry.op, true);
                if seen.insert((with.clone(), next.clone())) {
                    explored = match explored.checked_add(1) {
                        Some(explored) => explored,
                        None => return Ok(Search::Undecided(u64::MAX)),
                    };
                    if explored > limit.max_configurations {
                        return Ok(Search::Undecided(explored));
                    }
                    stack.push((at, state));
                    state = next;
                    linearized = with;
                    list.lift(at);
                    cursor = list.head;
                    taken = true;
                }
            }
            if !taken {
                cursor = entry.next;
            }
        } else {
            // A return whose call is not linearized: undo the last choice
            // and try the call after it.
            let Some((call, before)) = stack.pop() else {
                return Ok(Search::No);
            };
            let op = list.get(call).map_or(0, |entry| entry.op);
            linearized.set(op, false);
            state = before;
            list.unlift(call);
            cursor = list.get(call).and_then(|entry| entry.next);
        }
    }
}

/// Checks `history` against `model`, searching at most `limit`.
///
/// # Errors
///
/// [`HistoryError`] for a history that is not well formed.
pub fn check<M: Model>(
    model: &M,
    history: &History<M::Op, M::Ret>,
    limit: Limit,
) -> Result<Verdict<M::Op, M::Ret>, HistoryError> {
    match search(model, history, limit)? {
        Search::Order(order) => Ok(Verdict::Linearizable(order)),
        Search::Undecided(explored) => Ok(Verdict::Undecided { explored }),
        Search::No => {
            // The shortest prefix cut after a return that is already not
            // linearizable: prefixes are monotone (see the module).
            let (mut low, mut high) = (0usize, history.returns());
            while low < high {
                // Below `high`, so neither step overflows.
                let middle = (high - low) / 2 + low;
                match search(model, &history.up_to_return(middle), limit)? {
                    Search::No => high = middle,
                    Search::Order(_) => low = middle + 1,
                    Search::Undecided(explored) => return Ok(Verdict::Undecided { explored }),
                }
            }
            Ok(Verdict::NotLinearizable(Counterexample {
                prefix: history.up_to_return(high),
            }))
        }
    }
}
