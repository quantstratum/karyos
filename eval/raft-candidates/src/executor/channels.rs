// SPDX-License-Identifier: Apache-2.0

//! The channels and the mutex of [`SimRuntime`](super::SimRuntime):
//! `futures-channel`'s mpsc and oneshot, `futures-util`'s async mutex, and
//! a watch channel of its own. None spawns, sleeps or reads a clock: each
//! wakes the task waiting on it, and the executor polls it when pumped.

use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock, RwLockReadGuard, Weak};
use std::task::{Context, Poll, Waker};

use futures_channel::{mpsc, oneshot};
use openraft_rt::mpsc::{Mpsc, MpscReceiver, MpscSender, MpscWeakSender, SendError, TryRecvError};
use openraft_rt::watch::{RecvError, Watch, WatchReceiver, WatchSender};
use openraft_rt::{Oneshot, OneshotSender, OptionalSend, OptionalSync};

/// The mpsc channel: `futures-channel`'s bounded one.
#[derive(Debug, Clone, Copy)]
pub struct SimMpsc;

/// An mpsc sender. Its clones share one `futures-channel` sender, and
/// every send goes through it: the channel holds at most its buffer plus
/// that sender's one slot, whatever the number of clones or sends
/// (karyos#959 review: a fresh underlying sender per send had a slot of its
/// own and bypassed the capacity). The receiver sees the channel closed
/// once every clone is dropped, and a weak sender upgrades while one is
/// alive.
///
/// The underlying sender parks one waker, so every send blocked on a full
/// channel registers its own waker with the clones, and the waker handed to
/// the sender wakes them all: draining the channel resumes every blocked
/// send, not only the last one to register (karyos#959 review).
pub struct SimSender<T>(Arc<Mutex<MpscShared<T>>>);

/// What a sender's clones share.
struct MpscShared<T> {
    sender: mpsc::Sender<T>,
    blocked: Arc<Waiters>,
}

/// The wakers of the futures waiting on a channel (blocked sends, a
/// watch's waiting receivers). Each registration belongs to the future
/// that made it, under an id of its own, not to its task: two futures of
/// one task keep two registrations, and a future gives its own back when
/// it completes or is dropped (karyos#959 review). It holds at most one
/// waker per live waiting future.
#[derive(Default)]
struct Waiters(Mutex<(u64, Vec<(u64, Waker)>)>);

impl Waiters {
    /// Registers `waker` for the future whose registration is `slot`: a
    /// new one, or its existing one updated.
    fn register(&self, slot: &mut Option<u64>, waker: &Waker) {
        let mut guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let (next, waiting) = &mut *guard;
        if let Some(id) = *slot
            && let Some((_, known)) = waiting.iter_mut().find(|(at, _)| *at == id)
        {
            if !known.will_wake(waker) {
                known.clone_from(waker);
            }
            return;
        }
        // A new future, or one whose registration a wake took.
        let id = slot.unwrap_or_else(|| {
            let id = *next;
            *next = next.wrapping_add(1);
            id
        });
        *slot = Some(id);
        waiting.push((id, waker.clone()));
    }

    /// Gives back the registration of the future whose slot it is.
    fn unregister(&self, slot: &mut Option<u64>) {
        if let Some(id) = slot.take() {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .1
                .retain(|(at, _)| *at != id);
        }
    }

    /// Wakes every registered future, and drops their registrations.
    fn wake_all(&self) {
        let waiting = std::mem::take(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner).1);
        for (_, waker) in waiting {
            waker.wake();
        }
    }

    /// The registrations (tests).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .1
            .len()
    }
}

impl std::task::Wake for Waiters {
    fn wake(self: Arc<Self>) {
        self.wake_all();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_all();
    }
}

impl<T> Clone for SimSender<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> fmt::Debug for SimSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimSender").finish_non_exhaustive()
    }
}

/// A weak mpsc sender.
pub struct SimWeakSender<T>(Weak<Mutex<MpscShared<T>>>);

impl<T> Clone for SimWeakSender<T> {
    fn clone(&self) -> Self {
        Self(Weak::clone(&self.0))
    }
}

/// An mpsc receiver.
pub struct SimReceiver<T>(mpsc::Receiver<T>);

impl Mpsc for SimMpsc {
    type Sender<T: OptionalSend> = SimSender<T>;
    type Receiver<T: OptionalSend> = SimReceiver<T>;
    type WeakSender<T: OptionalSend> = SimWeakSender<T>;

    fn channel<T: OptionalSend>(buffer: usize) -> (Self::Sender<T>, Self::Receiver<T>) {
        let (sender, receiver) = mpsc::channel(buffer);
        (
            SimSender(Arc::new(Mutex::new(MpscShared {
                sender,
                blocked: Arc::default(),
            }))),
            SimReceiver(receiver),
        )
    }
}

/// A send in flight. It holds its task's registration only while it waits
/// on a full channel, and gives it back when it completes or is dropped
/// (cancelled by a timeout or another branch), so no registration outlives
/// the send that made it (karyos#959 review).
struct SendFuture<T> {
    shared: Arc<Mutex<MpscShared<T>>>,
    msg: Option<T>,
    /// Its registration while blocked.
    slot: Option<u64>,
}

impl<T> SendFuture<T> {
    fn release(&mut self) {
        if self.slot.is_some() {
            self.shared
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .blocked
                .unregister(&mut self.slot);
        }
    }
}

impl<T> Unpin for SendFuture<T> {}

impl<T> Future for SendFuture<T> {
    type Output = Result<(), SendError<T>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let Some(value) = this.msg.take() else {
            // Polled again after it finished: nothing left to send.
            return Poll::Pending;
        };
        let mut shared = this.shared.lock().unwrap_or_else(PoisonError::into_inner);
        let MpscShared { sender, blocked } = &mut *shared;
        // Registered before polling, so a wake between the two is kept.
        blocked.register(&mut this.slot, cx.waker());
        let all = Waker::from(Arc::clone(blocked));
        let ready = sender.poll_ready(&mut Context::from_waker(&all));
        if ready.is_ready() {
            blocked.unregister(&mut this.slot);
        }
        match ready {
            Poll::Pending => {
                this.msg = Some(value);
                Poll::Pending
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(SendError(value))),
            Poll::Ready(Ok(())) => Poll::Ready(
                sender
                    .try_send(value)
                    .map_err(|error| SendError(error.into_inner())),
            ),
        }
    }
}

impl<T> Drop for SendFuture<T> {
    fn drop(&mut self) {
        self.release();
    }
}

impl<T: OptionalSend> MpscSender<SimMpsc, T> for SimSender<T> {
    fn send(&self, msg: T) -> impl Future<Output = Result<(), SendError<T>>> + OptionalSend {
        SendFuture {
            shared: Arc::clone(&self.0),
            msg: Some(msg),
            slot: None,
        }
    }

    fn downgrade(&self) -> SimWeakSender<T> {
        SimWeakSender(Arc::downgrade(&self.0))
    }
}

impl<T: OptionalSend> MpscWeakSender<SimMpsc, T> for SimWeakSender<T> {
    fn upgrade(&self) -> Option<SimSender<T>> {
        self.0.upgrade().map(SimSender)
    }
}

impl<T: OptionalSend> MpscReceiver<T> for SimReceiver<T> {
    fn recv(&mut self) -> impl Future<Output = Option<T>> + OptionalSend {
        let receiver = &mut self.0;
        poll_fn(move |cx| futures_util::stream::Stream::poll_next(Pin::new(&mut *receiver), cx))
    }

    fn try_recv(&mut self) -> Result<T, TryRecvError> {
        match self.0.try_recv() {
            Ok(value) => Ok(value),
            Err(mpsc::TryRecvError::Closed) => Err(TryRecvError::Disconnected),
            Err(mpsc::TryRecvError::Empty) => Err(TryRecvError::Empty),
        }
    }
}

/// The oneshot channel: `futures-channel`'s.
#[derive(Debug, Clone, Copy)]
pub struct SimOneshot;

/// A oneshot sender.
pub struct SimOneshotSender<T>(oneshot::Sender<T>);

impl Oneshot for SimOneshot {
    type Sender<T: OptionalSend> = SimOneshotSender<T>;
    type Receiver<T: OptionalSend> = oneshot::Receiver<T>;
    type ReceiverError = oneshot::Canceled;

    fn channel<T>() -> (Self::Sender<T>, Self::Receiver<T>)
    where
        T: OptionalSend,
    {
        let (sender, receiver) = oneshot::channel();
        (SimOneshotSender(sender), receiver)
    }
}

impl<T: OptionalSend> OneshotSender<T> for SimOneshotSender<T> {
    fn send(self, t: T) -> Result<(), T> {
        self.0.send(t)
    }
}

/// The async mutex: `futures-util`'s.
pub struct SimMutex<T>(futures_util::lock::Mutex<T>);

impl<T: OptionalSend + 'static> openraft_rt::Mutex<T> for SimMutex<T> {
    type Guard<'a>
        = futures_util::lock::MutexGuard<'a, T>
    where
        Self: 'a;

    fn new(value: T) -> Self {
        Self(futures_util::lock::Mutex::new(value))
    }

    fn lock(&self) -> impl Future<Output = Self::Guard<'_>> + OptionalSend {
        self.0.lock()
    }
}

/// The watch channel: one value, a version, and the tasks waiting for a
/// newer one.
#[derive(Debug, Clone, Copy)]
pub struct SimWatch;

struct Shared<T> {
    value: RwLock<T>,
    version: AtomicU64,
    senders: AtomicUsize,
    receivers: AtomicUsize,
    waiting: Waiters,
}

impl<T> Shared<T> {
    fn read(&self) -> RwLockReadGuard<'_, T> {
        self.value.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn wake_all(&self) {
        self.waiting.wake_all();
    }

    fn bump(&self) {
        let _ = self.version.fetch_add(1, Ordering::SeqCst);
        self.wake_all();
    }
}

/// A watch sender.
pub struct SimWatchSender<T>(Arc<Shared<T>>);

/// A watch receiver.
pub struct SimWatchReceiver<T> {
    shared: Arc<Shared<T>>,
    seen: u64,
}

impl<T> Clone for SimWatchSender<T> {
    fn clone(&self) -> Self {
        let _ = self.0.senders.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(&self.0))
    }
}

impl<T> Drop for SimWatchSender<T> {
    fn drop(&mut self) {
        if self.0.senders.fetch_sub(1, Ordering::SeqCst) == 1 {
            // The last sender: waiting receivers see the channel closed.
            self.0.wake_all();
        }
    }
}

impl<T> Clone for SimWatchReceiver<T> {
    fn clone(&self) -> Self {
        let _ = self.shared.receivers.fetch_add(1, Ordering::SeqCst);
        Self {
            shared: Arc::clone(&self.shared),
            seen: self.seen,
        }
    }
}

impl<T> Drop for SimWatchReceiver<T> {
    fn drop(&mut self) {
        let _ = self.shared.receivers.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Watch for SimWatch {
    type Sender<T: OptionalSend + OptionalSync> = SimWatchSender<T>;
    type Receiver<T: OptionalSend + OptionalSync> = SimWatchReceiver<T>;
    type Ref<'a, T: OptionalSend + 'a> = RwLockReadGuard<'a, T>;

    fn channel<T: OptionalSend + OptionalSync>(init: T) -> (Self::Sender<T>, Self::Receiver<T>) {
        let shared = Arc::new(Shared {
            value: RwLock::new(init),
            version: AtomicU64::new(0),
            senders: AtomicUsize::new(1),
            receivers: AtomicUsize::new(1),
            waiting: Waiters::default(),
        });
        (
            SimWatchSender(Arc::clone(&shared)),
            SimWatchReceiver { shared, seen: 0 },
        )
    }
}

impl<T: OptionalSend + OptionalSync> WatchSender<SimWatch, T> for SimWatchSender<T> {
    fn send(&self, value: T) -> Result<(), openraft_rt::watch::SendError<T>> {
        // As Tokio's: with no receiver left the value is refused.
        if self.0.receivers.load(Ordering::SeqCst) == 0 {
            return Err(openraft_rt::watch::SendError(value));
        }
        *self.0.value.write().unwrap_or_else(PoisonError::into_inner) = value;
        self.0.bump();
        Ok(())
    }

    fn send_if_modified<F>(&self, modify: F) -> bool
    where
        F: FnOnce(&mut T) -> bool,
    {
        let modified = modify(&mut self.0.value.write().unwrap_or_else(PoisonError::into_inner));
        if modified {
            self.0.bump();
        }
        modified
    }

    fn borrow_watched(&self) -> RwLockReadGuard<'_, T> {
        self.0.read()
    }

    fn subscribe(&self) -> SimWatchReceiver<T> {
        let _ = self.0.receivers.fetch_add(1, Ordering::SeqCst);
        SimWatchReceiver {
            shared: Arc::clone(&self.0),
            seen: self.0.version.load(Ordering::SeqCst),
        }
    }
}

/// A receiver waiting for a change. Like a send, it holds its own
/// registration only while it waits, and gives it back when it completes
/// or is dropped (karyos#959 review).
struct Changed<'a, T> {
    receiver: &'a mut SimWatchReceiver<T>,
    slot: Option<u64>,
}

impl<T> Unpin for Changed<'_, T> {}

impl<T> Future for Changed<'_, T> {
    type Output = Result<(), RecvError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let shared = Arc::clone(&this.receiver.shared);
        let changed = |receiver: &mut SimWatchReceiver<T>| {
            let version = shared.version.load(Ordering::SeqCst);
            (version != receiver.seen).then(|| receiver.seen = version)
        };
        if changed(this.receiver).is_some() {
            shared.waiting.unregister(&mut this.slot);
            return Poll::Ready(Ok(()));
        }
        if shared.senders.load(Ordering::SeqCst) == 0 {
            shared.waiting.unregister(&mut this.slot);
            return Poll::Ready(Err(RecvError(())));
        }
        shared.waiting.register(&mut this.slot, cx.waker());
        // A send, or the last sender's drop, between the checks and the
        // registration is seen now: an unseen final value first, then the
        // closure (karyos#959 review).
        if changed(this.receiver).is_some() {
            shared.waiting.unregister(&mut this.slot);
            return Poll::Ready(Ok(()));
        }
        if shared.senders.load(Ordering::SeqCst) == 0 {
            shared.waiting.unregister(&mut this.slot);
            return Poll::Ready(Err(RecvError(())));
        }
        Poll::Pending
    }
}

impl<T> Drop for Changed<'_, T> {
    fn drop(&mut self) {
        if self.slot.is_some() {
            self.receiver.shared.waiting.unregister(&mut self.slot);
        }
    }
}

impl<T: OptionalSend + OptionalSync> WatchReceiver<SimWatch, T> for SimWatchReceiver<T> {
    async fn changed(&mut self) -> Result<(), RecvError> {
        Changed {
            receiver: self,
            slot: None,
        }
        .await
    }

    fn borrow_watched(&self) -> RwLockReadGuard<'_, T> {
        self.shared.read()
    }

    fn borrow_and_update(&mut self) -> RwLockReadGuard<'_, T> {
        self.seen = self.shared.version.load(Ordering::SeqCst);
        self.shared.read()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::Executor;

    fn registered<T>(sender: &SimSender<T>) -> usize {
        sender
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .blocked
            .len()
    }

    /// The karyos#959 review: sends that complete leave no registration,
    /// and a task that blocks over and over holds one, however many polls
    /// and sends it makes.
    #[test]
    fn the_waker_registry_holds_only_blocked_tasks_once() {
        let executor = Executor::new(1);
        let (sender, mut receiver) = SimMpsc::channel::<u64>(4);
        let probe = sender.clone();
        let _handle = executor.spawn(async move {
            for value in 0..1_000u64 {
                if sender.send(value).await.is_err() {
                    return;
                }
            }
        });
        let mut received = 0u64;
        let mut most = 0usize;
        for _ in 0..2_000 {
            let _ = executor.pump(16);
            most = most.max(registered(&probe));
            // One read per round: the sender blocks again and again.
            if receiver.try_recv().is_ok() {
                received += 1;
            }
        }
        assert_eq!(received, 1_000);
        assert!(most <= 1, "{most} registrations for one task");
        assert_eq!(registered(&probe), 0);
    }

    /// A task's waker, one per task (`Waker::noop` would make every task
    /// the same to `will_wake`); it counts its wakes.
    #[derive(Default)]
    struct Flag(std::sync::atomic::AtomicUsize);

    impl std::task::Wake for Flag {
        fn wake(self: Arc<Self>) {
            let _ = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// The remaining part of the karyos#959 review: a send cancelled while
    /// the channel is full gives its registration back. Ten sends, each
    /// polled once by its own task's waker and then dropped, leave none.
    #[test]
    fn a_cancelled_blocked_send_leaves_no_registration() {
        let (sender, _receiver) = SimMpsc::channel::<u64>(0);
        let mut first = sender.send(0);
        let waker = Waker::from(Arc::new(Flag::default()));
        let mut context = Context::from_waker(&waker);
        // The channel's one slot is taken: every later send blocks.
        assert!(Pin::new(&mut first).poll(&mut context).is_ready());
        for value in 1..=10 {
            let waker = Waker::from(Arc::new(Flag::default()));
            let mut context = Context::from_waker(&waker);
            let mut send = sender.send(value);
            assert!(Pin::new(&mut send).poll(&mut context).is_pending());
            assert_eq!(registered(&sender), 1);
            drop(send);
            assert_eq!(registered(&sender), 0);
        }
    }

    /// The karyos#959 review: two sends of one task each keep their own
    /// registration, so dropping one leaves the other's in place and it is
    /// woken when the channel drains.
    #[test]
    fn two_sends_of_one_task_keep_their_own_registrations() {
        let (sender, mut receiver) = SimMpsc::channel::<u64>(0);
        let flag = Arc::new(Flag::default());
        let waker = Waker::from(Arc::clone(&flag));
        let mut context = Context::from_waker(&waker);
        let mut first = sender.send(0);
        assert!(Pin::new(&mut first).poll(&mut context).is_ready());
        let mut kept = sender.send(1);
        let mut dropped = sender.send(2);
        assert!(Pin::new(&mut kept).poll(&mut context).is_pending());
        assert!(Pin::new(&mut dropped).poll(&mut context).is_pending());
        assert_eq!(registered(&sender), 2);
        drop(dropped);
        assert_eq!(registered(&sender), 1);
        assert_eq!(receiver.try_recv().ok(), Some(0));
        assert!(
            flag.0.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "the kept send was woken"
        );
        assert!(Pin::new(&mut kept).poll(&mut context).is_ready());
        assert_eq!(registered(&sender), 0);
    }

    /// The karyos#959 review: a watch receiver whose wait is cancelled
    /// gives its registration back.
    #[test]
    fn a_cancelled_watch_wait_leaves_no_registration() {
        use openraft_rt::watch::{Watch, WatchReceiver, WatchSender};

        let (sender, mut receiver) = SimWatch::channel(0u64);
        for _ in 0..10 {
            let waker = Waker::from(Arc::new(Flag::default()));
            let mut context = Context::from_waker(&waker);
            let mut wait = Box::pin(receiver.changed());
            assert!(wait.as_mut().poll(&mut context).is_pending());
            drop(wait);
        }
        assert_eq!(sender.0.waiting.len(), 0);
        sender.send(1).unwrap();
        let waker = Waker::from(Arc::new(Flag::default()));
        let mut context = Context::from_waker(&waker);
        assert!(
            Box::pin(receiver.changed())
                .as_mut()
                .poll(&mut context)
                .is_ready()
        );
    }
}
