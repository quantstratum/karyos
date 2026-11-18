// SPDX-License-Identifier: Apache-2.0

//! The bounded, manually pumped executor (plan issue 076, karyos#690):
//! nothing runs unless pumped, a pump is bounded, sleeps end only when
//! the clock is moved, and the same calls reproduce the same
//! interleaving.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use karyos_raft_eval::executor::{Event, Executor, JoinError, SimRuntime};
use openraft_rt::{AsyncRuntime, Instant as _};
use rand::RngExt as _;

#[test]
fn nothing_runs_until_pumped() {
    let executor = Executor::new(1);
    let ran = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&ran);
    let _handle = executor.spawn(async move {
        counter.fetch_add(1, Ordering::SeqCst);
    });
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    assert_eq!(executor.woken(), 1);
    let pumped = executor.pump(16);
    assert_eq!((pumped.polls, pumped.left), (1, 0));
    assert_eq!(ran.load(Ordering::SeqCst), 1);
}

/// A task that always wakes itself is cut at the budget, which says what
/// was left: a pump never runs unboundedly.
#[test]
fn a_pump_stops_at_its_budget() {
    let executor = Executor::new(1);
    let polls = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&polls);
    let _handle = executor.spawn(std::future::poll_fn(move |cx| {
        counter.fetch_add(1, Ordering::SeqCst);
        cx.waker().wake_by_ref();
        std::task::Poll::<()>::Pending
    }));
    let pumped = executor.pump(10);
    assert_eq!((pumped.polls, pumped.left), (10, 1));
    assert_eq!(polls.load(Ordering::SeqCst), 10);
}

#[test]
fn a_sleep_ends_only_when_the_clock_reaches_it() {
    let executor = Executor::new(1);
    let woke = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&woke);
    executor.enter(|| {
        let _handle = SimRuntime::spawn(async move {
            SimRuntime::sleep(Duration::from_millis(5)).await;
            *slot.lock().unwrap() = Some(<SimRuntime as AsyncRuntime>::Instant::now().millis());
        });
    });
    let _ = executor.pump(16);
    assert_eq!(executor.next_deadline(), Some(5));
    executor.advance_to(4);
    let _ = executor.pump(16);
    assert_eq!(*woke.lock().unwrap(), None);
    executor.advance_to(5);
    let _ = executor.pump(16);
    assert_eq!(*woke.lock().unwrap(), Some(5));
    assert_eq!(executor.next_deadline(), None);
}

#[test]
fn a_timeout_elapses_on_the_virtual_clock() {
    let executor = Executor::new(1);
    let result = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&result);
    executor.enter(|| {
        let _handle = SimRuntime::spawn(async move {
            let outcome =
                SimRuntime::timeout(Duration::from_millis(3), std::future::pending::<()>()).await;
            *slot.lock().unwrap() = Some(outcome.is_err());
        });
    });
    let _ = executor.pump(16);
    executor.advance_to(3);
    let _ = executor.pump(16);
    assert_eq!(*result.lock().unwrap(), Some(true));
}

#[test]
fn a_spawn_with_no_current_executor_says_so() {
    let handle = SimRuntime::spawn(async {});
    let executor = Executor::new(1);
    let result = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&result);
    let _outer = executor.spawn(async move {
        *slot.lock().unwrap() = Some(handle.await);
    });
    let _ = executor.pump(16);
    assert_eq!(*result.lock().unwrap(), Some(Err(JoinError::NoExecutor)));
}

/// Tasks that spawn, sleep, draw random numbers and talk over channels:
/// run twice from the same seed and calls, the interleaving (every
/// spawn, poll, completion and clock move) and the draws are the same;
/// from another seed the draws differ.
fn scenario(seed: u64) -> (Vec<Event>, u64, Vec<u64>) {
    let executor = Executor::new(seed);
    let draws = Arc::new(Mutex::new(Vec::new()));
    executor.enter(|| {
        for task in 0..4u64 {
            let draws = Arc::clone(&draws);
            let _handle = SimRuntime::spawn(async move {
                for round in 0..3u64 {
                    let wait = SimRuntime::thread_rng().random_range(1..10u64);
                    draws.lock().unwrap().push(wait);
                    SimRuntime::sleep(Duration::from_millis(wait + task + round)).await;
                    let _inner = SimRuntime::spawn(async {});
                }
            });
        }
    });
    for now in 0..60 {
        executor.advance_to(now);
        let _ = executor.pump(64);
    }
    let draws = draws.lock().unwrap().clone();
    (executor.trace(), executor.trace_digest(), draws)
}

#[test]
fn the_same_seed_reproduces_the_same_interleaving() {
    let first = scenario(7);
    assert_eq!(first, scenario(7));
    assert!(first.0.iter().any(|event| matches!(event, Event::Clock(_))));
    assert_ne!(first.2, scenario(8).2);
}
