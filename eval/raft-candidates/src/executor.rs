// SPDX-License-Identifier: Apache-2.0

//! A bounded, manually pumped executor behind `openraft-rt`'s
//! [`AsyncRuntime`] (owner item 33: "OpenRaft default features off, with a
//! bounded, manually pumped executor behind its runtime abstraction";
//! plan issue 076, karyos#690).
//!
//! - **Manually pumped.** Nothing runs by itself: no thread, no timer
//!   thread, no I/O. [`Executor::pump`] polls the tasks that were woken, in
//!   the order they were woken, and returns; [`Executor::advance_to`]
//!   moves the executor's virtual clock and wakes the sleeps that fell due.
//!   The caller (the adapter, under the simulator) decides when either
//!   happens, so the run is a function of the caller's calls.
//! - **Bounded.** One pump polls at most its budget of tasks and reports
//!   what was left ([`Pumped::left`]), so a pump never runs unboundedly and
//!   no work hides outside the measurement.
//! - **Deterministic.** Task ids, the wake queue, the timers and the RNG are
//!   ordered and seeded: the same calls reproduce the same interleaving,
//!   which [`Executor::trace`] records and the tests compare.
//! - **Current executor.** `AsyncRuntime`'s functions are static, so
//!   [`Executor::enter`] makes an executor current on the thread for the
//!   duration of a call, as Tokio's runtime context does. A spawn with no
//!   current executor gives a handle that resolves to
//!   [`JoinError::NoExecutor`].
//!
//! The executor and its primitives are `Send` and `Sync` (OpenRaft without
//! `single-threaded` requires it) but are driven from one thread.
//!
//! **Time.** One virtual millisecond is one harness tick: [`SimInstant`]
//! counts milliseconds since the executor started.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use futures_channel::oneshot;
use openraft_rt::{AsyncRuntime, OptionalSend};
use rand::SeedableRng;
use rand::rngs::SmallRng;

pub mod channels;

/// A task's future.
type Task = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Polls one pump takes at most, unless the caller gives another budget.
pub const DEFAULT_BUDGET: usize = 4096;

/// What the executor did, in order: the interleaving a seed must
/// reproduce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Task `id` was spawned.
    Spawned(u64),
    /// Task `id` was polled and is still pending.
    Pending(u64),
    /// Task `id` finished.
    Finished(u64),
    /// Task `id` panicked; it is dropped and its handle reports it.
    Panicked(u64),
    /// The clock moved to this millisecond.
    Clock(u64),
}

/// Trace entries kept at most: the oldest are dropped past it, and
/// [`Executor::trace_digest`] still covers every event.
pub const TRACE_KEPT: usize = 1 << 16;

#[derive(Default)]
struct State {
    /// The tasks, by id; `None` while one is being polled.
    tasks: BTreeMap<u64, Option<Task>>,
    /// Each live task's waker, made once and reused for every poll, so a
    /// waiter can recognise the task it already holds (`will_wake`).
    wakers: BTreeMap<u64, Waker>,
    /// Woken tasks, in wake order, each at most once.
    ready: VecDeque<u64>,
    queued: BTreeSet<u64>,
    next_id: u64,
    /// The virtual clock, in milliseconds.
    now: u64,
    /// Sleeps waiting, by deadline then registration order.
    timers: BTreeMap<(u64, u64), Waker>,
    next_timer: u64,
    /// The RNG's state: each draw seeds a new generator from it.
    seed: u64,
    trace: VecDeque<Event>,
    /// A digest of every event, the dropped ones included.
    digest: u64,
    /// Polls over the executor's life.
    polls: u64,
}

impl State {
    fn record(&mut self, event: Event) {
        let code = match event {
            Event::Spawned(id) => id.rotate_left(8) ^ 1,
            Event::Pending(id) => id.rotate_left(8) ^ 2,
            Event::Finished(id) => id.rotate_left(8) ^ 3,
            Event::Panicked(id) => id.rotate_left(8) ^ 4,
            Event::Clock(now) => now.rotate_left(8) ^ 5,
        };
        // A hash: modular arithmetic is its definition.
        self.digest = splitmix64(self.digest ^ code);
        if self.trace.len() == TRACE_KEPT {
            let _ = self.trace.pop_front();
        }
        self.trace.push_back(event);
    }

    fn wake(&mut self, id: u64) {
        if self.tasks.contains_key(&id) && self.queued.insert(id) {
            self.ready.push_back(id);
        }
    }

    /// Drops a finished task's pending wake: a task that woke itself in
    /// its last poll leaves no entry for a later pump to skip outside its
    /// budget (karyos#959 review). The queue then names live tasks only.
    fn forget_wake(&mut self, id: u64) {
        if self.queued.remove(&id) {
            self.ready.retain(|queued| *queued != id);
        }
    }
}

/// SplitMix64: the executor's RNG step and trace hash (a hash: wrapping
/// arithmetic is its definition).
#[must_use]
pub fn splitmix64(seed: u64) -> u64 {
    let z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    let z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    // The executor never panics while it holds its lock; a poisoned lock
    // still holds a consistent state.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The waker `block_on` gives its root future: it records a wake.
#[derive(Default)]
struct RootWaker(AtomicBool);

impl Wake for RootWaker {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct TaskWaker {
    state: Weak<Mutex<State>>,
    id: u64,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if let Some(state) = self.state.upgrade() {
            lock(&state).wake(self.id);
        }
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Arc<Mutex<State>>>> = const { RefCell::new(None) };
}

fn current() -> Option<Arc<Mutex<State>>> {
    CURRENT.with(|current| {
        current
            .try_borrow()
            .ok()
            .and_then(|current| current.clone())
    })
}

/// What one [`Executor::pump`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pumped {
    /// Tasks polled.
    pub polls: usize,
    /// Tasks still woken when the budget ran out: 0 when the pump went
    /// idle.
    pub left: usize,
}

/// The bounded, manually pumped executor (see the module).
#[derive(Clone)]
pub struct Executor {
    state: Arc<Mutex<State>>,
}

impl fmt::Debug for Executor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock(&self.state);
        f.debug_struct("Executor")
            .field("now", &state.now)
            .field("tasks", &state.tasks.len())
            .field("ready", &state.ready.len())
            .field("timers", &state.timers.len())
            .finish()
    }
}

impl Executor {
    /// An executor at millisecond 0 whose RNG starts from `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                seed,
                ..State::default()
            })),
        }
    }

    /// Runs `call` with this executor current on the thread: what it
    /// spawns, its sleeps and its clock reads are this executor's. The
    /// previous current executor is restored after.
    pub fn enter<R>(&self, call: impl FnOnce() -> R) -> R {
        let previous = CURRENT.with(|current| {
            current
                .try_borrow_mut()
                .ok()
                .and_then(|mut current| current.replace(Arc::clone(&self.state)))
        });
        let result = call();
        CURRENT.with(|current| {
            if let Ok(mut current) = current.try_borrow_mut() {
                *current = previous;
            }
        });
        result
    }

    /// Spawns `future` on this executor.
    pub fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        spawn_on(&self.state, future)
    }

    /// Polls the woken tasks, at most `budget` of them, in wake order.
    pub fn pump(&self, budget: usize) -> Pumped {
        self.enter(|| {
            let mut polls = 0usize;
            while polls < budget {
                let Some((id, mut task)) = ({
                    let mut state = lock(&self.state);
                    let next = state.ready.pop_front();
                    next.and_then(|id| {
                        let _ = state.queued.remove(&id);
                        let task = state.tasks.get_mut(&id).and_then(Option::take)?;
                        state.polls = state.polls.saturating_add(1);
                        Some((id, task))
                    })
                }) else {
                    if lock(&self.state).ready.is_empty() {
                        break;
                    }
                    continue;
                };
                // Below `budget`, so it does not overflow.
                polls += 1;
                let waker = lock(&self.state)
                    .wakers
                    .entry(id)
                    .or_insert_with(|| {
                        Waker::from(Arc::new(TaskWaker {
                            state: Arc::downgrade(&self.state),
                            id,
                        }))
                    })
                    .clone();
                let mut context = Context::from_waker(&waker);
                let polled = catch_unwind(AssertUnwindSafe(|| task.as_mut().poll(&mut context)));
                let mut state = lock(&self.state);
                match polled {
                    Ok(Poll::Pending) => {
                        if let Some(slot) = state.tasks.get_mut(&id) {
                            *slot = Some(task);
                        }
                        state.record(Event::Pending(id));
                    }
                    Ok(Poll::Ready(())) => {
                        let _ = state.tasks.remove(&id);
                        let _ = state.wakers.remove(&id);
                        state.forget_wake(id);
                        state.record(Event::Finished(id));
                    }
                    Err(_) => {
                        let _ = state.tasks.remove(&id);
                        let _ = state.wakers.remove(&id);
                        state.forget_wake(id);
                        state.record(Event::Panicked(id));
                    }
                }
            }
            Pumped {
                polls,
                left: lock(&self.state).ready.len(),
            }
        })
    }

    /// Moves the clock to `now` milliseconds (never back) and wakes the
    /// sleeps due by then.
    pub fn advance_to(&self, now: u64) {
        let mut due = Vec::new();
        {
            let mut state = lock(&self.state);
            if now <= state.now {
                return;
            }
            state.now = now;
            state.record(Event::Clock(now));
            while let Some(entry) = state.timers.first_entry() {
                if entry.key().0 > now {
                    break;
                }
                due.push(entry.remove());
            }
        }
        // Woken without the lock: a task's waker takes it.
        for waker in due {
            waker.wake();
        }
    }

    /// The clock, in milliseconds.
    #[must_use]
    pub fn now(&self) -> u64 {
        lock(&self.state).now
    }

    /// Tasks alive.
    #[must_use]
    pub fn tasks(&self) -> usize {
        lock(&self.state).tasks.len()
    }

    /// Tasks woken and not yet polled.
    #[must_use]
    pub fn woken(&self) -> usize {
        lock(&self.state).ready.len()
    }

    /// The earliest sleep's deadline, if any sleeps.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        lock(&self.state).timers.keys().next().map(|(at, _)| *at)
    }

    /// The last [`TRACE_KEPT`] events.
    #[must_use]
    pub fn trace(&self) -> Vec<Event> {
        lock(&self.state).trace.iter().copied().collect()
    }

    /// A digest of every event since the start.
    #[must_use]
    pub fn trace_digest(&self) -> u64 {
        lock(&self.state).digest
    }

    /// Polls since the start.
    #[must_use]
    pub fn polls(&self) -> u64 {
        lock(&self.state).polls
    }
}

fn spawn_on<F>(state: &Arc<Mutex<State>>, future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let (sender, receiver) = oneshot::channel();
    let task: Task = Box::pin(async move {
        let output = future.await;
        let _ = sender.send(output);
    });
    let mut state = lock(state);
    let id = state.next_id;
    state.next_id = id.saturating_add(1);
    let _ = state.tasks.insert(id, Some(task));
    state.wake(id);
    state.record(Event::Spawned(id));
    JoinHandle {
        receiver: Some(receiver),
    }
}

/// Why a task gave no output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinError {
    /// It panicked, or was dropped with its executor.
    Dropped,
    /// It was spawned with no current executor.
    NoExecutor,
}

impl fmt::Display for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dropped => f.write_str("the task panicked or its executor dropped it"),
            Self::NoExecutor => f.write_str("the task was spawned with no current executor"),
        }
    }
}

impl std::error::Error for JoinError {}

/// A spawned task's output.
#[derive(Debug)]
pub struct JoinHandle<T> {
    /// `None` when it was spawned with no executor.
    receiver: Option<oneshot::Receiver<T>>,
}

impl<T> Future for JoinHandle<T> {
    type Output = Result<T, JoinError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let Some(receiver) = this.receiver.as_mut() else {
            return Poll::Ready(Err(JoinError::NoExecutor));
        };
        Pin::new(receiver)
            .poll(cx)
            .map(|output| output.map_err(|_| JoinError::Dropped))
    }
}

/// The executor's virtual instant: milliseconds since its start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct SimInstant(u64);

impl SimInstant {
    /// The instant `millis` after the start.
    #[must_use]
    pub fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// Milliseconds since the start.
    #[must_use]
    pub fn millis(self) -> u64 {
        self.0
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

impl Add<Duration> for SimInstant {
    type Output = Self;

    fn add(self, duration: Duration) -> Self {
        // Time saturates at the end of u64 milliseconds: a deadline that
        // far is never reached, which is the meaning of an unbounded wait.
        Self(self.0.saturating_add(millis(duration)))
    }
}

impl AddAssign<Duration> for SimInstant {
    fn add_assign(&mut self, duration: Duration) {
        *self = *self + duration;
    }
}

impl Sub<Duration> for SimInstant {
    type Output = Self;

    fn sub(self, duration: Duration) -> Self {
        // Before the start is the start.
        Self(self.0.saturating_sub(millis(duration)))
    }
}

impl SubAssign<Duration> for SimInstant {
    fn sub_assign(&mut self, duration: Duration) {
        *self = *self - duration;
    }
}

impl Sub<SimInstant> for SimInstant {
    type Output = Duration;

    fn sub(self, earlier: Self) -> Duration {
        // A later instant minus an earlier one; the other way is zero.
        Duration::from_millis(self.0.saturating_sub(earlier.0))
    }
}

impl openraft_rt::Instant for SimInstant {
    fn now() -> Self {
        Self(current().map_or(0, |state| lock(&state).now))
    }
}

/// A sleep until a virtual deadline.
#[derive(Debug)]
pub struct Sleep {
    deadline: u64,
    /// Its timer, while registered.
    timer: Option<u64>,
    state: Option<Weak<Mutex<State>>>,
}

impl Sleep {
    fn until(deadline: SimInstant) -> Self {
        Self {
            deadline: deadline.0,
            timer: None,
            state: current().map(|state| Arc::downgrade(&state)),
        }
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        // With no executor, a sleep never ends.
        let Some(state) = this.state.as_ref().and_then(Weak::upgrade) else {
            return Poll::Pending;
        };
        let mut state = lock(&state);
        if state.now >= this.deadline {
            if let Some(timer) = this.timer.take() {
                let _ = state.timers.remove(&(this.deadline, timer));
            }
            return Poll::Ready(());
        }
        let timer = match this.timer {
            Some(timer) => timer,
            None => {
                let timer = state.next_timer;
                state.next_timer = timer.saturating_add(1);
                this.timer = Some(timer);
                timer
            }
        };
        let _ = state
            .timers
            .insert((this.deadline, timer), cx.waker().clone());
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let (Some(timer), Some(state)) =
            (self.timer, self.state.as_ref().and_then(Weak::upgrade))
        {
            let _ = lock(&state).timers.remove(&(self.deadline, timer));
        }
    }
}

/// A future that ran past its deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elapsed;

impl fmt::Display for Elapsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("deadline elapsed")
    }
}

impl std::error::Error for Elapsed {}

/// `future`, or [`Elapsed`] at its deadline.
pub struct Timeout<F> {
    future: Pin<Box<F>>,
    sleep: Sleep,
}

impl<F> fmt::Debug for Timeout<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Timeout")
            .field("sleep", &self.sleep)
            .finish_non_exhaustive()
    }
}

impl<R, F: Future<Output = R>> Future for Timeout<F> {
    type Output = Result<R, Elapsed>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Poll::Ready(output) = this.future.as_mut().poll(cx) {
            return Poll::Ready(Ok(output));
        }
        Pin::new(&mut this.sleep).poll(cx).map(|()| Err(Elapsed))
    }
}

/// The executor as OpenRaft's runtime (see the module).
#[derive(Debug, Clone)]
pub struct SimRuntime {
    executor: Executor,
}

impl SimRuntime {
    /// The executor this runtime pumps.
    #[must_use]
    pub fn executor(&self) -> &Executor {
        &self.executor
    }
}

impl AsyncRuntime for SimRuntime {
    type JoinError = JoinError;
    type JoinHandle<T: OptionalSend + 'static> = JoinHandle<T>;
    type Sleep = Sleep;
    type Instant = SimInstant;
    type TimeoutError = Elapsed;
    type Timeout<R, T: Future<Output = R> + OptionalSend> = Timeout<T>;
    type ThreadLocalRng = SmallRng;
    type Mpsc = channels::SimMpsc;
    type Watch = channels::SimWatch;
    type Oneshot = channels::SimOneshot;
    type Mutex<T: OptionalSend + 'static> = channels::SimMutex<T>;

    fn spawn<T>(future: T) -> Self::JoinHandle<T::Output>
    where
        T: Future + OptionalSend + 'static,
        T::Output: OptionalSend + 'static,
    {
        match current() {
            Some(state) => spawn_on(&state, future),
            None => JoinHandle { receiver: None },
        }
    }

    fn sleep(duration: Duration) -> Self::Sleep {
        Sleep::until(<SimInstant as openraft_rt::Instant>::now() + duration)
    }

    fn sleep_until(deadline: Self::Instant) -> Self::Sleep {
        Sleep::until(deadline)
    }

    fn timeout<R, F: Future<Output = R> + OptionalSend>(
        duration: Duration,
        future: F,
    ) -> Self::Timeout<R, F> {
        Timeout {
            future: Box::pin(future),
            sleep: Self::sleep(duration),
        }
    }

    fn timeout_at<R, F: Future<Output = R> + OptionalSend>(
        deadline: Self::Instant,
        future: F,
    ) -> Self::Timeout<R, F> {
        Timeout {
            future: Box::pin(future),
            sleep: Sleep::until(deadline),
        }
    }

    fn is_panic(join_error: &Self::JoinError) -> bool {
        *join_error == JoinError::Dropped
    }

    fn thread_rng() -> Self::ThreadLocalRng {
        let seed = current().map_or(0, |state| {
            let mut state = lock(&state);
            state.seed = splitmix64(state.seed);
            state.seed
        });
        SmallRng::seed_from_u64(seed)
    }

    fn new(_threads: usize) -> Self {
        Self {
            executor: Executor::new(0),
        }
    }

    fn block_on<F, T>(&mut self, future: F) -> T
    where
        F: Future<Output = T>,
    {
        // Polled here, on the caller's stack, with this executor current:
        // between polls the executor's tasks are pumped and, when none is
        // woken, its clock moves to the next deadline (or by a millisecond).
        let executor = self.executor.clone();
        let mut future = Box::pin(future);
        // The root future's own wakes are kept, so work it made ready at
        // the current time is polled before the clock moves (karyos#959
        // review).
        let woken = Arc::new(RootWaker::default());
        let waker = Waker::from(Arc::clone(&woken));
        let mut context = Context::from_waker(&waker);
        loop {
            let polled = executor.enter(|| future.as_mut().poll(&mut context));
            if let Poll::Ready(output) = polled {
                return output;
            }
            let pumped = executor.pump(DEFAULT_BUDGET);
            if pumped.polls == 0 && !woken.0.swap(false, Ordering::SeqCst) {
                let next = executor
                    .next_deadline()
                    .unwrap_or_else(|| executor.now().saturating_add(1));
                executor.advance_to(next.max(executor.now().saturating_add(1)));
            }
        }
    }
}
