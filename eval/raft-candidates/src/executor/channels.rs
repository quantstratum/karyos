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
    blocked: Arc<Blocked>,
}

/// The wakers of the sends blocked on a full channel.
#[derive(Default)]
struct Blocked(Mutex<Vec<Waker>>);

impl Blocked {
    /// Registers a send's task, once: the executor reuses each task's
    /// waker across polls, so `will_wake` recognises it, and the registry
    /// holds at most one waker per task blocked on the channel.
    fn register(&self, waker: &Waker) {
        let mut wakers = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if !wakers.iter().any(|known| known.will_wake(waker)) {
            wakers.push(waker.clone());
        }
    }

    /// Drops a send's registration once it no longer waits: a send that
    /// completes leaves nothing behind (karyos#959 review).
    fn unregister(&self, waker: &Waker) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|known| !known.will_wake(waker));
    }

    /// The registered wakers (tests).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).len()
    }
}

impl std::task::Wake for Blocked {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let wakers = std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner));
        for waker in wakers {
            waker.wake();
        }
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
    /// The waker registered while blocked.
    registered: Option<Waker>,
}

impl<T> SendFuture<T> {
    fn release(&mut self) {
        if let Some(waker) = self.registered.take() {
            self.shared
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .blocked
                .unregister(&waker);
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
        // Registered before polling, so a wake between the two is kept; a
        // new waker replaces the one this send held.
        if let Some(old) = this.registered.take()
            && !old.will_wake(cx.waker())
        {
            blocked.unregister(&old);
        }
        blocked.register(cx.waker());
        this.registered = Some(cx.waker().clone());
        let all = Waker::from(Arc::clone(blocked));
        let ready = sender.poll_ready(&mut Context::from_waker(&all));
        if ready.is_ready() {
            blocked.unregister(cx.waker());
            this.registered = None;
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
            registered: None,
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
    waiting: Mutex<Vec<Waker>>,
}

impl<T> Shared<T> {
    fn read(&self) -> RwLockReadGuard<'_, T> {
        self.value.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn wake_all(&self) {
        let waiting =
            std::mem::take(&mut *self.waiting.lock().unwrap_or_else(PoisonError::into_inner));
        for waker in waiting {
            waker.wake();
        }
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
            waiting: Mutex::new(Vec::new()),
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

impl<T: OptionalSend + OptionalSync> WatchReceiver<SimWatch, T> for SimWatchReceiver<T> {
    async fn changed(&mut self) -> Result<(), RecvError> {
        poll_fn(|cx: &mut Context<'_>| {
            let version = self.shared.version.load(Ordering::SeqCst);
            if version != self.seen {
                self.seen = version;
                return Poll::Ready(Ok(()));
            }
            if self.shared.senders.load(Ordering::SeqCst) == 0 {
                return Poll::Ready(Err(RecvError(())));
            }
            let mut waiting = self
                .shared
                .waiting
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if !waiting.iter().any(|waker| waker.will_wake(cx.waker())) {
                waiting.push(cx.waker().clone());
            }
            drop(waiting);
            // A send between the check and the registration is seen now.
            let version = self.shared.version.load(Ordering::SeqCst);
            if version != self.seen {
                self.seen = version;
                return Poll::Ready(Ok(()));
            }
            Poll::Pending
        })
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

    struct Flag;

    impl std::task::Wake for Flag {
        fn wake(self: Arc<Self>) {}
    }

    /// The remaining part of the karyos#959 review: a send cancelled while
    /// the channel is full gives its registration back. Ten sends, each
    /// polled once by its own task's waker and then dropped, leave none.
    #[test]
    fn a_cancelled_blocked_send_leaves_no_registration() {
        let (sender, _receiver) = SimMpsc::channel::<u64>(0);
        let mut first = sender.send(0);
        let waker = Waker::from(Arc::new(Flag));
        let mut context = Context::from_waker(&waker);
        // The channel's one slot is taken: every later send blocks.
        assert!(Pin::new(&mut first).poll(&mut context).is_ready());
        for value in 1..=10 {
            let waker = Waker::from(Arc::new(Flag));
            let mut context = Context::from_waker(&waker);
            let mut send = sender.send(value);
            assert!(Pin::new(&mut send).poll(&mut context).is_pending());
            assert_eq!(registered(&sender), 1);
            drop(send);
            assert_eq!(registered(&sender), 0);
        }
    }
}
