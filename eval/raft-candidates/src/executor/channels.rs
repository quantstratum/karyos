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

/// An mpsc sender. Its clones share one `futures-channel` sender, so
/// the receiver sees the channel closed once every clone is dropped, and
/// a weak sender upgrades while one is alive.
pub struct SimSender<T>(Arc<mpsc::Sender<T>>);

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
pub struct SimWeakSender<T>(Weak<mpsc::Sender<T>>);

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
        (SimSender(Arc::new(sender)), SimReceiver(receiver))
    }
}

impl<T: OptionalSend> MpscSender<SimMpsc, T> for SimSender<T> {
    fn send(&self, msg: T) -> impl Future<Output = Result<(), SendError<T>>> + OptionalSend {
        let mut sender = (*self.0).clone();
        async move {
            if poll_fn(|cx| sender.poll_ready(cx)).await.is_err() {
                return Err(SendError(msg));
            }
            sender
                .try_send(msg)
                .map_err(|error| SendError(error.into_inner()))
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
