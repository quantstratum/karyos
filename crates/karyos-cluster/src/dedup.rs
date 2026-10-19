// SPDX-License-Identifier: Apache-2.0

//! Client deduplication (quantstratum-docs:
//! karyos/design/cluster-dedup-and-snapshots.md §2, C7a), core neutral: a
//! table of client sessions driven only by applied log entries, so every
//! replica that applies the same entries holds the same table.
//!
//! - **Sessions.** A client registers under a stable identity and an
//!   epoch. The table holds at most [`DedupConfig::sessions`] live
//!   sessions; a registration that finds no free slot is refused
//!   ([`RegisterError::SessionsExhausted`]), and a live session is never
//!   evicted. A registration with a newer epoch replaces the client's
//!   session; an older one is refused ([`RegisterError::StaleEpoch`]).
//! - **Window** (design D1(b)). Each request carries its sequence and the
//!   lowest sequence the client has not yet seen answered. The session
//!   keeps the replies from that sequence up to its highest applied one,
//!   at most [`DedupConfig::window`] of them, each at most
//!   [`DedupConfig::response_bytes`] bytes. A request already applied and
//!   still in the window gets its retained reply ([`Outcome::Retained`]);
//!   one below the window, acknowledged by the client, gets
//!   [`Outcome::Duplicate`] without one; one past a full window is refused
//!   ([`Outcome::WindowFull`]). Sequences are applied in order: a request
//!   past the next sequence is refused ([`Outcome::OutOfOrder`]), so a
//!   request lost before the log is retried before its successors apply.
//! - **Replies.** The command runs once, in [`SessionTable::request`]'s
//!   `apply`, which writes its reply straight into the session's slot: one
//!   copy, no allocation. A reply that does not fit is recorded as such:
//!   the command's effects stand, and it and every retry get
//!   [`Outcome::ReplyTooLarge`]; the leader should refuse such a command
//!   before it is appended.
//! - **Expiry** (design D2(b)). Log time is the highest event time the
//!   table has applied, so it never goes back when a new leader's clock
//!   is behind. A session expires at the first entry whose log time is at
//!   least its last activity plus [`DedupConfig::ttl`]; every replica
//!   decides at the same entry. Expiry is checked when a session is
//!   looked up or a slot is sought, which gives the same answers as
//!   checking every session at every entry. An expired session's slot is
//!   free; its requests get [`Outcome::SessionExpired`], and the client
//!   registers again under a new epoch. A client must never reuse an
//!   epoch: the table forgets an expired one.
//! - **Activity.** Every request of a live session, retained and duplicate
//!   ones included, and every registration renew it. An idle client keeps
//!   its session with a no-op request at least every `ttl / 2`.
//! - **Memory.** [`SessionTable::new`] allocates `sessions × window ×
//!   response_bytes` reply bytes and the slot tables; nothing after. A
//!   lookup scans the sessions, `O(sessions)`.
//! - **Configuration.** The defaults are the design's proposal (owner item
//!   37, not decided yet): 1024 sessions, 64 replies, 8 KiB, 60 s. They
//!   are interim, and the owner's choice is a configuration change. The
//!   table returns its configuration at registration, so a client learns
//!   the bounds it is held to.
//!
//! Snapshots (C8) carry the table; its encoding comes with them.

#[cfg(test)]
mod tests;

/// The proposed sessions bound (design D3; interim, owner item 37).
pub const DEFAULT_SESSIONS: u32 = 1024;
/// The proposed replies per session (design D3; interim, owner item 37).
pub const DEFAULT_WINDOW: u32 = 64;
/// The proposed bytes per reply (design D3; interim, owner item 37).
pub const DEFAULT_RESPONSE_BYTES: u32 = 8 * 1024;
/// The proposed session expiry in log-time nanoseconds (design D3;
/// interim, owner item 37).
pub const DEFAULT_TTL: u64 = 60_000_000_000;

/// The table's bounds, advertised to a client at registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DedupConfig {
    /// Live sessions at most (`S`).
    pub sessions: u32,
    /// Replies retained per session (`K`).
    pub window: u32,
    /// Bytes per reply at most (`R`).
    pub response_bytes: u32,
    /// Session expiry, in log-time nanoseconds since its last activity.
    pub ttl: u64,
}

impl Default for DedupConfig {
    /// The design's proposal, interim until the owner decides (item 37).
    fn default() -> Self {
        Self {
            sessions: DEFAULT_SESSIONS,
            window: DEFAULT_WINDOW,
            response_bytes: DEFAULT_RESPONSE_BYTES,
            ttl: DEFAULT_TTL,
        }
    }
}

impl DedupConfig {
    /// With `sessions` live sessions at most.
    #[must_use]
    pub fn with_sessions(mut self, sessions: u32) -> Self {
        self.sessions = sessions;
        self
    }

    /// With `window` replies retained per session.
    #[must_use]
    pub fn with_window(mut self, window: u32) -> Self {
        self.window = window;
        self
    }

    /// With `response_bytes` bytes per reply at most.
    #[must_use]
    pub fn with_response_bytes(mut self, response_bytes: u32) -> Self {
        self.response_bytes = response_bytes;
        self
    }

    /// With sessions expiring `ttl` log-time nanoseconds after their last
    /// activity.
    #[must_use]
    pub fn with_ttl(mut self, ttl: u64) -> Self {
        self.ttl = ttl;
        self
    }
}

/// A configuration the table cannot hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A bound is zero.
    #[error("{0} is zero")]
    Zero(&'static str),
    /// The reply bytes overflow this platform's address space.
    #[error("sessions × window × response bytes overflows")]
    TooLarge,
}

/// A registration refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegisterError {
    /// Every slot holds a live session.
    #[error("every session slot is live")]
    SessionsExhausted,
    /// The client's live session has a newer epoch.
    #[error("the live session's epoch {current} is newer")]
    StaleEpoch {
        /// The live session's epoch.
        current: u64,
    },
}

/// A request as the log carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Request {
    /// The client's stable identity.
    pub client: u64,
    /// The epoch it registered under.
    pub epoch: u64,
    /// The request's sequence.
    pub sequence: u64,
    /// The lowest sequence the client has not seen answered: every reply
    /// below it may be dropped.
    pub lowest_unanswered: u64,
}

impl Request {
    /// Request `sequence` of `client` under `epoch`, the client having
    /// seen every reply below `lowest_unanswered`.
    #[must_use]
    pub fn new(client: u64, epoch: u64, sequence: u64, lowest_unanswered: u64) -> Self {
        Self {
            client,
            epoch,
            sequence,
            lowest_unanswered,
        }
    }
}

/// What a request's entry did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome<'a> {
    /// The command ran; its reply.
    Applied(&'a [u8]),
    /// Applied before: its retained reply. The command did not run again.
    Retained(&'a [u8]),
    /// Applied before, and the client has acknowledged its reply, which is
    /// gone. The command did not run again.
    Duplicate,
    /// The command ran, once, and its reply did not fit
    /// [`DedupConfig::response_bytes`].
    ReplyTooLarge,
    /// No live session holds this client and epoch: it expired, was
    /// closed, was never registered, or its registration is not applied
    /// yet. The client registers again under a new epoch; it must not
    /// assume the request was deduplicated.
    SessionExpired,
    /// The client's live session has a newer epoch.
    StaleEpoch,
    /// The window holds [`DedupConfig::window`] unacknowledged replies.
    WindowFull,
    /// The sequence is past the next one the session expects.
    OutOfOrder {
        /// The sequence the session expects.
        expected: u64,
    },
}

/// One session slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Session {
    live: bool,
    client: u64,
    epoch: u64,
    /// Log time of its last activity.
    activity: u64,
    /// The lowest sequence whose reply is retained.
    base: u64,
    /// The next sequence to apply.
    next: u64,
}

/// One retained reply's length, or a reply that did not fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Stored {
    #[default]
    Empty,
    Reply(u32),
    TooLarge,
}

/// The replicated session table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTable {
    config: DedupConfig,
    /// The highest event time applied.
    now: u64,
    sessions: Vec<Session>,
    /// `window` per session.
    stored: Vec<Stored>,
    /// `window × response_bytes` per session.
    replies: Vec<u8>,
}

impl SessionTable {
    /// An empty table, with every byte it will use allocated.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for a zero bound or reply bytes past the address
    /// space.
    pub fn new(config: DedupConfig) -> Result<Self, ConfigError> {
        for (name, value) in [
            ("sessions", config.sessions),
            ("window", config.window),
            ("response_bytes", config.response_bytes),
        ] {
            if value == 0 {
                return Err(ConfigError::Zero(name));
            }
        }
        if config.ttl == 0 {
            return Err(ConfigError::Zero("ttl"));
        }
        let sessions = usize::try_from(config.sessions).map_err(|_| ConfigError::TooLarge)?;
        let window = usize::try_from(config.window).map_err(|_| ConfigError::TooLarge)?;
        let bytes = usize::try_from(config.response_bytes).map_err(|_| ConfigError::TooLarge)?;
        let slots = sessions.checked_mul(window).ok_or(ConfigError::TooLarge)?;
        let reply_bytes = slots.checked_mul(bytes).ok_or(ConfigError::TooLarge)?;
        Ok(Self {
            config,
            now: 0,
            sessions: vec![Session::default(); sessions],
            stored: vec![Stored::Empty; slots],
            replies: vec![0; reply_bytes],
        })
    }

    /// The bounds, as advertised at registration.
    #[must_use]
    pub fn config(&self) -> DedupConfig {
        self.config
    }

    /// The log time: the highest event time applied.
    #[must_use]
    pub fn log_time(&self) -> u64 {
        self.now
    }

    /// The live sessions at the current log time.
    #[must_use]
    pub fn live_sessions(&self) -> usize {
        let now = self.now;
        let ttl = self.config.ttl;
        self.sessions
            .iter()
            .filter(|session| alive(session, now, ttl))
            .count()
    }

    /// Applies a registration of `client` under `epoch`, in an entry of
    /// event time `event_time`, and returns the bounds the session is held
    /// to. A registration of the live epoch again (a retried one) renews
    /// it; a newer epoch replaces the client's session, whose replies are
    /// gone.
    ///
    /// # Errors
    ///
    /// [`RegisterError`] for no free slot or an older epoch.
    pub fn register(
        &mut self,
        client: u64,
        epoch: u64,
        event_time: u64,
    ) -> Result<DedupConfig, RegisterError> {
        self.advance(event_time);
        let (now, ttl) = (self.now, self.config.ttl);
        let slot = match self.find(client) {
            Some(slot) => {
                let current = self.sessions.get(slot).map_or(0, |session| session.epoch);
                if epoch < current {
                    return Err(RegisterError::StaleEpoch { current });
                }
                if epoch == current {
                    if let Some(session) = self.sessions.get_mut(slot) {
                        session.activity = now;
                    }
                    return Ok(self.config);
                }
                slot
            }
            None => self
                .sessions
                .iter()
                .position(|session| !alive(session, now, ttl))
                .ok_or(RegisterError::SessionsExhausted)?,
        };
        if let Some(session) = self.sessions.get_mut(slot) {
            *session = Session {
                live: true,
                client,
                epoch,
                activity: now,
                base: 0,
                next: 0,
            };
        }
        Ok(self.config)
    }

    /// Applies a close of `client`'s session under `epoch`, freeing its
    /// slot; `false` if no live session holds them.
    pub fn close(&mut self, client: u64, epoch: u64, event_time: u64) -> bool {
        self.advance(event_time);
        let Some(slot) = self.find(client) else {
            return false;
        };
        match self.sessions.get_mut(slot) {
            Some(session) if session.epoch == epoch => {
                session.live = false;
                true
            }
            _ => false,
        }
    }

    /// Applies `request`, in an entry of event time `event_time`. A new
    /// request runs `apply` once, which writes its reply into the buffer it
    /// is given ([`DedupConfig::response_bytes`] long) and returns the
    /// reply's length, or `None` for a reply that does not fit; any other
    /// outcome leaves `apply` uncalled.
    pub fn request<F>(&mut self, request: Request, event_time: u64, apply: F) -> Outcome<'_>
    where
        F: FnOnce(&mut [u8]) -> Option<usize>,
    {
        self.advance(event_time);
        let Some(slot) = self.find(request.client) else {
            return Outcome::SessionExpired;
        };
        let now = self.now;
        let window = u64::from(self.config.window);
        let Some(session) = self.sessions.get_mut(slot) else {
            return Outcome::SessionExpired;
        };
        if request.epoch < session.epoch {
            return Outcome::StaleEpoch;
        }
        if request.epoch > session.epoch {
            return Outcome::SessionExpired;
        }
        session.activity = now;
        // The client has seen every reply below its lowest unanswered.
        session.base = request
            .lowest_unanswered
            .max(session.base)
            .min(session.next);
        let (base, next) = (session.base, session.next);
        if request.sequence < base {
            return Outcome::Duplicate;
        }
        if request.sequence < next {
            return match self.slot(slot, request.sequence) {
                Some((Stored::Reply(length), at)) => self
                    .reply(at, length)
                    .map_or(Outcome::Duplicate, Outcome::Retained),
                Some((Stored::TooLarge, _)) => Outcome::ReplyTooLarge,
                _ => Outcome::Duplicate,
            };
        }
        if request.sequence > next {
            return Outcome::OutOfOrder { expected: next };
        }
        if next.checked_sub(base).is_none_or(|held| held >= window) {
            return Outcome::WindowFull;
        }
        let Some(after) = next.checked_add(1) else {
            return Outcome::WindowFull;
        };
        let Some((_, at)) = self.slot(slot, request.sequence) else {
            return Outcome::SessionExpired;
        };
        let bytes = self.reply_capacity();
        let Some(buffer) = at
            .checked_add(bytes)
            .and_then(|end| self.replies.get_mut(at..end))
        else {
            return Outcome::SessionExpired;
        };
        let written = apply(buffer);
        let stored = match written.filter(|length| *length <= bytes) {
            Some(length) => u32::try_from(length).map_or(Stored::TooLarge, Stored::Reply),
            None => Stored::TooLarge,
        };
        if let Some(session) = self.sessions.get_mut(slot) {
            session.next = after;
        }
        if let Some(index) = self.stored_index(slot, request.sequence)
            && let Some(entry) = self.stored.get_mut(index)
        {
            *entry = stored;
        }
        match stored {
            Stored::Reply(length) => self
                .reply(at, length)
                .map_or(Outcome::ReplyTooLarge, Outcome::Applied),
            _ => Outcome::ReplyTooLarge,
        }
    }

    /// Moves log time to `event_time` if it is later.
    fn advance(&mut self, event_time: u64) {
        self.now = self.now.max(event_time);
    }

    /// The slot of `client`'s live session.
    fn find(&self, client: u64) -> Option<usize> {
        let (now, ttl) = (self.now, self.config.ttl);
        self.sessions
            .iter()
            .position(|session| session.client == client && alive(session, now, ttl))
    }

    fn reply_capacity(&self) -> usize {
        usize::try_from(self.config.response_bytes).unwrap_or(0)
    }

    /// The index in `stored` of `sequence`'s reply in session `slot`.
    fn stored_index(&self, slot: usize, sequence: u64) -> Option<usize> {
        let window = usize::try_from(self.config.window).ok()?;
        let offset = usize::try_from(sequence.checked_rem(u64::from(self.config.window))?).ok()?;
        slot.checked_mul(window)?.checked_add(offset)
    }

    /// What is stored for `sequence` in session `slot`, and where its
    /// bytes start.
    fn slot(&self, slot: usize, sequence: u64) -> Option<(Stored, usize)> {
        let index = self.stored_index(slot, sequence)?;
        let stored = *self.stored.get(index)?;
        Some((stored, index.checked_mul(self.reply_capacity())?))
    }

    /// The `length` reply bytes at `at`.
    fn reply(&self, at: usize, length: u32) -> Option<&[u8]> {
        let end = at.checked_add(usize::try_from(length).ok()?)?;
        self.replies.get(at..end)
    }
}

/// Whether `session` is live at log time `now`.
fn alive(session: &Session, now: u64, ttl: u64) -> bool {
    session.live
        && session
            .activity
            .checked_add(ttl)
            .is_none_or(|end| now < end)
}
