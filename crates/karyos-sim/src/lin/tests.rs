// SPDX-License-Identifier: Apache-2.0

// The linearizability checker: known linearizable and non-linearizable
// histories over a register and a counter, pending operations, the
// minimised counterexample (and the prefix monotonicity it relies on),
// the limit, and histories that are not well formed.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use super::*;

/// A register of one integer, read and written.
struct Register;

#[derive(Debug, Clone, PartialEq, Eq)]
enum RegisterOp {
    Write(u32),
    Read,
}

impl Model for Register {
    type State = u32;
    type Op = RegisterOp;
    type Ret = Option<u32>;

    fn init(&self) -> u32 {
        0
    }

    fn step(&self, state: &u32, op: &RegisterOp) -> (u32, Option<u32>) {
        match op {
            RegisterOp::Write(value) => (*value, None),
            RegisterOp::Read => (*state, Some(*state)),
        }
    }
}

/// A counter whose increment returns the value after it.
struct Counter;

impl Model for Counter {
    type State = u64;
    type Op = ();
    type Ret = u64;

    fn init(&self) -> u64 {
        0
    }

    fn step(&self, state: &u64, _: &()) -> (u64, u64) {
        (state + 1, state + 1)
    }
}

const ENOUGH: Limit = Limit {
    max_configurations: 1_000_000,
};

fn verdict<M: Model>(model: &M, history: &History<M::Op, M::Ret>) -> Verdict<M::Op, M::Ret> {
    check(model, history, ENOUGH).unwrap()
}

#[test]
fn a_sequential_history_is_linearizable_in_its_order() {
    let mut history = History::new();
    history
        .invoke(1, RegisterOp::Write(5))
        .ret(1, None)
        .invoke(2, RegisterOp::Read)
        .ret(2, Some(5));
    assert_eq!(
        verdict(&Register, &history),
        Verdict::Linearizable(vec![0, 1])
    );
    assert_eq!(
        verdict(&Register, &History::new()),
        Verdict::Linearizable(vec![])
    );
}

/// A read concurrent with a write may see either value; one that starts
/// after the write returned must see it.
#[test]
fn concurrency_admits_either_order_and_real_time_does_not() {
    let mut overlapping = History::new();
    overlapping
        .invoke(1, RegisterOp::Write(5))
        .invoke(2, RegisterOp::Read)
        .ret(2, Some(0))
        .ret(1, None);
    assert_eq!(
        verdict(&Register, &overlapping),
        Verdict::Linearizable(vec![1, 0])
    );
    // The stale read: the write returned before the read started.
    let mut stale = History::new();
    stale
        .invoke(1, RegisterOp::Write(5))
        .ret(1, None)
        .invoke(2, RegisterOp::Read)
        .ret(2, Some(0));
    assert!(matches!(
        verdict(&Register, &stale),
        Verdict::NotLinearizable(_)
    ));
}

/// Two concurrent increments both returning 1: one increment is lost.
#[test]
fn a_lost_increment_is_not_linearizable() {
    let mut history = History::new();
    history.invoke(1, ()).invoke(2, ()).ret(1, 1).ret(2, 1);
    let Verdict::NotLinearizable(counterexample) = verdict(&Counter, &history) else {
        panic!("linearized a lost increment");
    };
    assert_eq!(counterexample.prefix, history);
    let mut fine = History::new();
    fine.invoke(1, ()).invoke(2, ()).ret(1, 2).ret(2, 1);
    assert!(matches!(verdict(&Counter, &fine), Verdict::Linearizable(_)));
}

/// An operation that never returned may have taken effect, or not.
#[test]
fn a_pending_operation_is_taken_or_left_out() {
    // The pending write explains the read of 5.
    let mut taken = History::new();
    taken
        .invoke(1, RegisterOp::Write(5))
        .invoke(2, RegisterOp::Read)
        .ret(2, Some(5));
    assert_eq!(
        verdict(&Register, &taken),
        Verdict::Linearizable(vec![0, 1])
    );
    // The read of 0.
    let mut left = History::new();
    left.invoke(1, RegisterOp::Write(5))
        .invoke(2, RegisterOp::Read)
        .ret(2, Some(0));
    // Left out, or taken after the read: either explains it.
    assert!(matches!(
        verdict(&Register, &left),
        Verdict::Linearizable(order) if order.first() == Some(&1)
    ));
    // Nothing explains a read of 7.
    let mut neither = History::new();
    neither
        .invoke(1, RegisterOp::Write(5))
        .invoke(2, RegisterOp::Read)
        .ret(2, Some(7));
    assert!(matches!(
        verdict(&Register, &neither),
        Verdict::NotLinearizable(_)
    ));
}

/// The counterexample is the shortest prefix, cut after a return, that is
/// already not linearizable; every longer prefix is not either, and every
/// shorter one is (the monotonicity bisection relies on).
#[test]
fn the_counterexample_is_the_shortest_failing_prefix() {
    let mut history = History::new();
    history
        .invoke(1, RegisterOp::Write(1))
        .ret(1, None)
        .invoke(2, RegisterOp::Read)
        .ret(2, Some(1))
        // The stale read: 1 was written and read, then 0 is read.
        .invoke(3, RegisterOp::Read)
        .ret(3, Some(0))
        .invoke(1, RegisterOp::Write(2))
        .ret(1, None)
        .invoke(2, RegisterOp::Read)
        .ret(2, Some(2));
    let Verdict::NotLinearizable(counterexample) = verdict(&Register, &history) else {
        panic!("linearized a stale read");
    };
    assert_eq!(counterexample.prefix.events(), &history.events()[..6]);
    for count in 0..=history.returns() {
        let linearizable = matches!(
            verdict(&Register, &history.up_to_return(count)),
            Verdict::Linearizable(_)
        );
        assert_eq!(linearizable, count < 3, "prefix of {count} returns");
    }
}

/// A wide concurrent history whose search the limit stops: undecided,
/// never a guess.
#[test]
fn the_limit_gives_undecided() {
    let mut history = History::new();
    for client in 0..12 {
        history.invoke(client, ());
    }
    // All return 12 but the last, which returns 0: not linearizable, and
    // only an exhaustive search shows it.
    for client in 0..11 {
        history.ret(client, 12);
    }
    history.ret(11, 0);
    let small = Limit {
        max_configurations: 50,
    };
    assert!(matches!(
        check(&Counter, &history, small).unwrap(),
        Verdict::Undecided { explored: 51 }
    ));
}

#[test]
fn a_history_that_is_not_well_formed_is_refused() {
    let mut twice = History::new();
    twice.invoke(1, ()).invoke(1, ());
    assert_eq!(
        check(&Counter, &twice, ENOUGH),
        Err(HistoryError::InvokeWhileOpen { client: 1 })
    );
    let mut orphan: History<(), u64> = History::new();
    orphan.ret(2, 1);
    assert_eq!(
        check(&Counter, &orphan, ENOUGH),
        Err(HistoryError::ReturnWithoutInvoke { client: 2 })
    );
}
