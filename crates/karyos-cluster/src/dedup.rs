// SPDX-License-Identifier: Apache-2.0

//! Client deduplication (quantstratum-docs:
//! karyos/design/cluster-dedup-and-snapshots.md §2, C7a), core neutral: a
//! table of client sessions driven only by applied log entries, so every
//! replica that applies the same entries holds the same table.
//!
//! - **Sessions.** A client registers under its stable identity, and the
//!   session's epoch is the registering entry's log index (the Raft
//!   dissertation's §6.3): [`SessionTable::register`] returns it, and the
//!   client's requests carry it. Every registration entry opens a new
//!   session, so a late duplicate of a registration opens another session
//!   under a later epoch and never revives an expired or closed one: an
//!   epoch is used once, and a request of an epoch whose session is gone
//!   is refused for good. The table holds at most
//!   [`DedupConfig::sessions`] live sessions, a client possibly several (a
//!   duplicate registration's session expires unused); a registration that
//!   finds no free slot is refused ([`RegisterError::SessionsExhausted`]),
//!   and a live session is never evicted. Registrations must come in
//!   increasing log order ([`RegisterError::NotAfter`]).
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
//!   registers again, which gives it a new epoch.
//! - **Activity.** Every request of a live session, retained and duplicate
//!   ones included, and every registration renew it. An idle client keeps
//!   its session with a no-op request at least every `ttl / 2`.
//! - **Memory.** [`SessionTable::new`] allocates `sessions × window ×
//!   response_bytes` reply bytes and the slot tables; nothing after. A
//!   lookup scans the sessions, `O(sessions)`.
//!   [`DedupConfig::reserved_bytes`] is that reservation, metadata
//!   included, per replica.
//! - **Configuration** (item 37 of the decisions of 2026-10-21,
//!   `decisions.md` in quantstratum-docs). Two profiles; the large one is
//!   had only by naming it:
//!
//! | Profile | Sessions | Replies | Bytes per reply | TTL | Reserved per replica |
//! | --- | --- | --- | --- | --- | --- |
//! | [`DedupConfig::default`] | 64 | 64 | 8 KiB | 60 s | 33,590,272 B (32 MiB and 35 KiB of metadata) |
//! | [`DedupConfig::large`] | 1024 | 64 | 8 KiB | 60 s | 537,444,352 B (512 MiB and 560 KiB of metadata) |
//!
//!   A cluster reserves this on every replica: three replicas of the
//!   large profile reserve over 1.5 GiB. Every number here is
//!   provisional: they are initial evaluation values, to be measured in C5
//!   W1 and W2 before the phase 4 gate ([plan issue 069], karyos#685); a
//!   change is a configuration change. The table returns its
//!   configuration at registration, so a client learns the bounds it is
//!   held to.
//!
//!
//! [plan issue 069]: https://github.com/quantstratum/quantstratum-docs/blob/main/karyos/issues/M04-replicated-cluster/069-measure-the-dedup-and-snapshot-defaults.md
//!
//! - **Snapshots** (C8). [`SessionTable::encode`] writes the table as a
//!   snapshot's sessions section ([`SESSIONS_VERSION`]), and
//!   [`SessionTable::decode`] rebuilds it: the configuration, the log time,
//!   the last registration's index, and every session live at the log time
//!   with its slot, client, epoch, activity, window and retained replies.
//!   A decoded table answers every later entry as the encoded one would,
//!   and encodes to the same bytes. Little endian:
//!
//! | Field | Bytes |
//! | --- | --- |
//! | magic `KRDT`, version | 4, 4 |
//! | sessions, window, response bytes, ttl | 4, 4, 4, 8 |
//! | log time | 8 |
//! | last registration: 1 and its index, or 0 and 0 | 1, 8 |
//! | live sessions | 4 |
//! | per session: slot, client, epoch, activity, base, next | 4, 8 × 5 |
//! | per retained sequence from base to next: 1 and its length and bytes, or 2 for a reply too large | 1, 4, length |
//!
//! Decoding checks every bound: a slot past the table, a window past
//! [`DedupConfig::window`], a reply past [`DedupConfig::response_bytes`],
//! two sessions in one slot or under one client and epoch, a session not
//! live at the log time or active after it, an epoch past the last
//! registration, or bytes left over are [`DecodeError`].

#[cfg(test)]
mod tests;

/// The sessions section's version.
pub const SESSIONS_VERSION: u64 = 1;
const SESSIONS_MAGIC: [u8; 4] = *b"KRDT";
/// The encoding's own version, inside the section.
const ENCODING_VERSION: u32 = 1;

/// A sessions section that does not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// Not this version's bytes, or bytes cut short or left over.
    #[error("not a sessions section of this version")]
    Format,
    /// Its configuration cannot be held.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// A session breaks the table's bounds.
    #[error("session at slot {slot} breaks the table's bounds")]
    Session {
        /// Its slot.
        slot: u32,
    },
}

/// The sessions bound of the default profile: the large profile's
/// replies, bytes and TTL for fewer clients (karyos#692).
pub const DEFAULT_SESSIONS: u32 = 64;
/// The sessions bound of [`DedupConfig::large`] (design D3; item 37's
/// initial value, to be measured).
pub const LARGE_SESSIONS: u32 = 1024;
/// The replies per session (design D3; item 37's initial value, to be
/// measured).
pub const DEFAULT_WINDOW: u32 = 64;
/// The bytes per reply (design D3; item 37's initial value, to be measured).
pub const DEFAULT_RESPONSE_BYTES: u32 = 8 * 1024;
/// The session expiry in log-time nanoseconds (design D3; item 37's
/// initial value, to be measured).
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
    /// The default profile: [`DedupConfig::large`] with
    /// [`DEFAULT_SESSIONS`] sessions, about 32 MiB per replica.
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
    /// The large profile, item 37's initial values: 1024 sessions, 64
    /// replies of 8 KiB, 60 s, 512 MiB of replies per replica before
    /// metadata ([`DedupConfig::reserved_bytes`]). Never the default.
    #[must_use]
    pub fn large() -> Self {
        Self::default().with_sessions(LARGE_SESSIONS)
    }

    /// The bytes [`SessionTable::new`] reserves for this configuration,
    /// per replica: the replies and the metadata, the session slots and
    /// the reply lengths. `None` when the product overflows.
    #[must_use]
    pub fn reserved_bytes(&self) -> Option<u64> {
        let sessions = u64::from(self.sessions);
        let slots = sessions.checked_mul(u64::from(self.window))?;
        let metadata = sessions
            .checked_mul(size_of::<Session>() as u64)?
            .checked_add(slots.checked_mul(size_of::<Stored>() as u64)?)?;
        slots
            .checked_mul(u64::from(self.response_bytes))?
            .checked_add(metadata)
    }

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
    /// The registration's log index is not past the previous one's: the
    /// entries are not applied in log order.
    #[error("registration at index {index}, not past {last}")]
    NotAfter {
        /// The registration's index.
        index: u64,
        /// The previous registration's.
        last: u64,
    },
}

/// A session opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Registered {
    /// The session's epoch: the registering entry's log index.
    pub epoch: u64,
    /// The bounds the session is held to.
    pub config: DedupConfig,
}

/// A request as the log carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Request {
    /// The client's stable identity.
    pub client: u64,
    /// Its session's epoch, as [`SessionTable::register`] returned it.
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
    /// closed, or was never opened. The client registers again, under a
    /// new epoch; it must not assume the request was deduplicated.
    SessionExpired,
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
    /// The last registration's log index.
    registered: Option<u64>,
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
            registered: None,
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

    /// Applies a registration of `client` in the entry at log index
    /// `index`, of event time `event_time`: opens a session whose epoch is
    /// `index`, and returns it with the bounds it is held to.
    ///
    /// # Errors
    ///
    /// [`RegisterError::SessionsExhausted`] for no free slot, and
    /// [`RegisterError::NotAfter`] for an index not past the previous
    /// registration's; neither opens a session.
    pub fn register(
        &mut self,
        client: u64,
        index: u64,
        event_time: u64,
    ) -> Result<Registered, RegisterError> {
        if let Some(last) = self.registered.filter(|last| index <= *last) {
            return Err(RegisterError::NotAfter { index, last });
        }
        self.advance(event_time);
        self.registered = Some(index);
        let (now, ttl) = (self.now, self.config.ttl);
        let slot = self
            .sessions
            .iter()
            .position(|session| !alive(session, now, ttl))
            .ok_or(RegisterError::SessionsExhausted)?;
        if let Some(session) = self.sessions.get_mut(slot) {
            *session = Session {
                live: true,
                client,
                epoch: index,
                activity: now,
                base: 0,
                next: 0,
            };
        }
        Ok(Registered {
            epoch: index,
            config: self.config,
        })
    }

    /// Applies an entry of event time `event_time` that holds no session
    /// operation, which still moves the log time on, so that every replica
    /// expires sessions at the same entry.
    pub fn observe(&mut self, event_time: u64) {
        self.advance(event_time);
    }

    /// Applies a close of `client`'s session `epoch`, freeing its slot;
    /// `false` if no live session holds them.
    pub fn close(&mut self, client: u64, epoch: u64, event_time: u64) -> bool {
        self.advance(event_time);
        let Some(slot) = self.find(client, epoch) else {
            return false;
        };
        if let Some(session) = self.sessions.get_mut(slot) {
            session.live = false;
        }
        true
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
        let Some(slot) = self.find(request.client, request.epoch) else {
            return Outcome::SessionExpired;
        };
        let now = self.now;
        let window = u64::from(self.config.window);
        let Some(session) = self.sessions.get_mut(slot) else {
            return Outcome::SessionExpired;
        };
        session.activity = now;
        // The client has seen every reply below its lowest unanswered. The
        // base never goes back: a late duplicate carries an older one.
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

    /// The table as a snapshot's sessions section (see the module).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (now, ttl) = (self.now, self.config.ttl);
        let live: Vec<(usize, &Session)> = self
            .sessions
            .iter()
            .enumerate()
            .filter(|(_, session)| alive(session, now, ttl))
            .collect();
        let mut out = Vec::new();
        out.extend_from_slice(&SESSIONS_MAGIC);
        out.extend_from_slice(&ENCODING_VERSION.to_le_bytes());
        out.extend_from_slice(&self.config.sessions.to_le_bytes());
        out.extend_from_slice(&self.config.window.to_le_bytes());
        out.extend_from_slice(&self.config.response_bytes.to_le_bytes());
        out.extend_from_slice(&self.config.ttl.to_le_bytes());
        out.extend_from_slice(&self.now.to_le_bytes());
        out.push(u8::from(self.registered.is_some()));
        out.extend_from_slice(&self.registered.unwrap_or(0).to_le_bytes());
        let count = u32::try_from(live.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for (slot, session) in live {
            out.extend_from_slice(&u32::try_from(slot).unwrap_or(u32::MAX).to_le_bytes());
            for field in [
                session.client,
                session.epoch,
                session.activity,
                session.base,
                session.next,
            ] {
                out.extend_from_slice(&field.to_le_bytes());
            }
            let mut sequence = session.base;
            while sequence < session.next {
                match self.slot(slot, sequence) {
                    Some((Stored::Reply(length), at)) => {
                        let reply = self.reply(at, length);
                        debug_assert!(reply.is_some(), "a retained reply is within its slot");
                        out.push(1);
                        out.extend_from_slice(&length.to_le_bytes());
                        out.extend_from_slice(reply.unwrap_or_default());
                    }
                    stored => {
                        // Every sequence in the window holds a reply or a
                        // reply too large.
                        debug_assert!(
                            matches!(stored, Some((Stored::TooLarge, _))),
                            "{stored:?} in a window"
                        );
                        out.push(2);
                    }
                }
                let Some(after) = sequence.checked_add(1) else {
                    break;
                };
                sequence = after;
            }
        }
        out
    }

    /// The table a sessions section holds, allocated whole as
    /// [`SessionTable::new`] does.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] for bytes that are not a section this version
    /// wrote, a configuration the table cannot hold, or a session outside
    /// its bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut input = Input(bytes);
        if input.array::<4>()? != SESSIONS_MAGIC
            || u32::from_le_bytes(input.array()?) != ENCODING_VERSION
        {
            return Err(DecodeError::Format);
        }
        let config = DedupConfig {
            sessions: u32::from_le_bytes(input.array()?),
            window: u32::from_le_bytes(input.array()?),
            response_bytes: u32::from_le_bytes(input.array()?),
            ttl: u64::from_le_bytes(input.array()?),
        };
        let mut table = Self::new(config)?;
        table.now = u64::from_le_bytes(input.array()?);
        let [flag] = input.array::<1>()?;
        let registered = u64::from_le_bytes(input.array()?);
        table.registered = match (flag, registered) {
            (0, 0) => None,
            (1, index) => Some(index),
            _ => return Err(DecodeError::Format),
        };
        let count = u32::from_le_bytes(input.array()?);
        let capacity = table.reply_capacity();
        for _ in 0..count {
            let slot = u32::from_le_bytes(input.array()?);
            let broken = DecodeError::Session { slot };
            let index = usize::try_from(slot).map_err(|_| broken)?;
            let [client, epoch, activity, base, next] =
                [(); 5].map(|()| input.array().map(u64::from_le_bytes));
            let session = Session {
                live: true,
                client: client?,
                epoch: epoch?,
                activity: activity?,
                base: base?,
                next: next?,
            };
            let held = session.next.checked_sub(session.base).ok_or(broken)?;
            // An epoch is a registration's index, and a session is active
            // no later than the log time.
            if held > u64::from(config.window)
                || !alive(&session, table.now, config.ttl)
                || session.activity > table.now
                || table.registered.is_none_or(|last| session.epoch > last)
                || table.sessions.get(index).is_none_or(|taken| taken.live)
                || table.sessions.iter().any(|other| {
                    other.live && (other.client, other.epoch) == (session.client, session.epoch)
                })
            {
                return Err(broken);
            }
            let mut sequence = session.base;
            while sequence < session.next {
                let (_, at) = table.slot(index, sequence).ok_or(broken)?;
                let entry = table.stored_index(index, sequence).ok_or(broken)?;
                let [kind] = input.array::<1>()?;
                let value = match kind {
                    1 => {
                        let length = u32::from_le_bytes(input.array()?);
                        let size = usize::try_from(length).map_err(|_| broken)?;
                        if size > capacity {
                            return Err(broken);
                        }
                        let bytes = input.take(size)?;
                        let end = at.checked_add(size).ok_or(broken)?;
                        table
                            .replies
                            .get_mut(at..end)
                            .ok_or(broken)?
                            .copy_from_slice(bytes);
                        Stored::Reply(length)
                    }
                    2 => Stored::TooLarge,
                    _ => return Err(DecodeError::Format),
                };
                *table.stored.get_mut(entry).ok_or(broken)? = value;
                sequence = sequence.checked_add(1).ok_or(broken)?;
            }
            *table.sessions.get_mut(index).ok_or(broken)? = session;
        }
        if !input.0.is_empty() {
            return Err(DecodeError::Format);
        }
        Ok(table)
    }

    /// Moves log time to `event_time` if it is later.
    fn advance(&mut self, event_time: u64) {
        self.now = self.now.max(event_time);
    }

    /// The slot of `client`'s live session `epoch`.
    fn find(&self, client: u64, epoch: u64) -> Option<usize> {
        let (now, ttl) = (self.now, self.config.ttl);
        self.sessions.iter().position(|session| {
            session.client == client && session.epoch == epoch && alive(session, now, ttl)
        })
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

/// Bytes being decoded.
struct Input<'a>(&'a [u8]);

impl<'a> Input<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        if length > self.0.len() {
            return Err(DecodeError::Format);
        }
        let (head, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let (head, rest) = self.0.split_first_chunk::<N>().ok_or(DecodeError::Format)?;
        self.0 = rest;
        Ok(*head)
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
