// SPDX-License-Identifier: Apache-2.0

//! The reference runner's semantic adapter (`conformance/FORMAT.md`,
//! format 2, The semantic layer; ADR-0073): each `op` run as a minimal
//! binding over the C ABI runs it, with the binding rules the suite pins
//! rather than the raw C answers. An object keeps its closed state, so a
//! second close after a successful one is `ok` and any other op on it, or
//! on a child of a closed parent, answers `closed`; a claim keeps its
//! staged state across the retryable statuses.

use std::collections::BTreeMap;
use std::ffi::CString;

use super::abi;
use crate::Value;

/// What an object is, for the ops that take it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Driver,
    Client,
    Publication,
    Subscription,
    Conflated,
    Claim,
    /// An Archive connection (`archive-replay`).
    Archive,
}

/// The Archive's control streams a runner's karyosd serves
/// (FORMAT.md, Archive replays).
const ARCHIVE_REQUESTS: i32 = 1030;
const ARCHIVE_RESPONSES: i32 = 1031;
/// How long an Archive connection, and a replay subscription's grant,
/// waits: the suite's constant (FORMAT.md, Archive replays).
const ARCHIVE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
/// The next Archive connection's requester id: 100, 200 and up, so no
/// connection's id, nor its replayer's (one more), meets another's.
static NEXT_ARCHIVE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(100);
/// How long `subscription.poll_to_end` polls for the end: past a replay
/// target's linger (FORMAT.md, Ops).
const END_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

/// How long a poll with `until` waits for its count (FORMAT.md, Ops).
const UNTIL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// An object a scenario holds: its C handle, its parent and whether its
/// own close succeeded.
#[derive(Debug)]
struct Object {
    kind: Kind,
    handle: u64,
    parent: Option<usize>,
    closed: bool,
    /// The runner's, not the scenario's: its close only ends its use in
    /// the scenario.
    provided: bool,
    /// An embedded driver created with its network on
    /// (`driver.create_networked`).
    networked: bool,
    /// A publication on a `karyos:udp` channel, which connects
    /// asynchronously.
    network: bool,
}

/// The answer of an op: `ok` with its results, or a status name.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    Ok(BTreeMap<String, Value>),
    Status(String),
    /// A status with results: an Archive's refusal and its response code.
    StatusWith(String, BTreeMap<String, Value>),
}

/// The statuses a commit answers while its claim stays staged
/// (`karyos_claim_commit`; BIND-S3).
const RETRYABLE: [&str; 5] = [
    "back_pressured",
    "not_connected",
    "admin_action",
    "rate_limited",
    "gated",
];

/// The objects of one scenario run.
pub struct Adapter {
    objects: Vec<Object>,
    names: BTreeMap<i32, String>,
    /// The replays the scenario started and did not see stop: its
    /// Archive connection's object, and the replay id.
    replays: Vec<(usize, u64)>,
}

impl Adapter {
    /// An adapter whose status names come from the header's `statuses`.
    pub fn new(statuses: &BTreeMap<String, i32>) -> Self {
        let names = statuses
            .iter()
            .filter_map(|(name, code)| {
                let name = name.strip_prefix("KARYOS_E_")?.to_ascii_lowercase();
                Some((*code, name))
            })
            .collect();
        Self {
            objects: Vec::new(),
            names,
            replays: Vec::new(),
        }
    }

    /// The client of an Archive-hosting driver a runner offering
    /// `archive-replay` provides (FORMAT.md, Archive replays): the
    /// runner's, which the scenario uses but does not close.
    pub fn provided_client(&mut self, client: u64) -> Value {
        let value = self.insert(Kind::Client, client, None);
        if let Some(object) = self.objects.last_mut() {
            object.provided = true;
        }
        value
    }

    /// The driver a runner without `embedded-driver` provides: started,
    /// serving streams 1 to 15 with the default stream options
    /// (FORMAT.md, The provided driver). The reference runner provides it
    /// from its own embedded driver.
    pub fn provided_driver(&mut self) -> Value {
        let (status, driver) = abi::driver_create();
        assert_eq!(status, 0, "the provided driver: karyos_driver_create");
        for stream_id in 1..=15 {
            let (status, options) = abi::stream_options(stream_id);
            assert_eq!(status, 0, "the provided driver: karyos_stream_options_init");
            let (status, _) = abi::driver_add_stream(driver, &options);
            assert_eq!(status, 0, "the provided driver: stream {stream_id}");
        }
        // The ABI's declared default idle strategy, yield then sleep.
        assert_eq!(abi::driver_start(driver, 3, 0), 0, "the provided driver");
        self.insert(Kind::Driver, driver, None)
    }

    /// Closes the objects a scenario left open, children first, so the
    /// next scenario starts from nothing.
    pub fn close_all(&mut self) {
        // The replays it started and did not see stop are stopped first:
        // closing an Archive connection leaves its replays running.
        for (archive, replay_id) in std::mem::take(&mut self.replays) {
            if !self.is_closed(archive) {
                let _ = abi::archive_stop_replay(self.objects[archive].handle, replay_id);
            }
        }
        for index in (0..self.objects.len()).rev() {
            if self.is_closed(index) || self.objects[index].provided {
                continue;
            }
            let handle = self.objects[index].handle;
            let _ = match self.objects[index].kind {
                Kind::Driver => abi::driver_close(handle),
                Kind::Client => abi::client_close(handle),
                Kind::Publication => abi::publication_close(handle),
                Kind::Subscription => abi::subscription_close(handle),
                Kind::Conflated => abi::conflated_close(handle),
                Kind::Claim => abi::claim_abort(handle),
                Kind::Archive => abi::archive_close(handle),
            };
            self.objects[index].closed = true;
        }
    }

    fn insert(&mut self, kind: Kind, handle: u64, parent: Option<usize>) -> Value {
        self.objects.push(Object {
            kind,
            handle,
            parent,
            closed: false,
            provided: false,
            networked: false,
            network: false,
        });
        Value::Object(self.objects.len() - 1)
    }

    /// Whether the object or one of its parents is closed.
    fn is_closed(&self, mut index: usize) -> bool {
        loop {
            let object = &self.objects[index];
            if object.closed {
                return true;
            }
            match object.parent {
                Some(parent) => index = parent,
                None => return false,
            }
        }
    }

    fn name(&self, code: i32, at: &str) -> String {
        self.names
            .get(&code)
            .cloned()
            .unwrap_or_else(|| panic!("{at}: status {code} is not in the header"))
    }

    /// The answer to a C status with no results.
    fn plain(&self, code: i32, at: &str) -> Answer {
        if code == 0 {
            Answer::Ok(BTreeMap::new())
        } else {
            Answer::Status(self.name(code, at))
        }
    }

    /// One `poll`, or with `until` given, polls (serving `object`'s client)
    /// until the delivered total reaches it or [`UNTIL_DEADLINE`] passes:
    /// the first failing status, else the total.
    fn poll_until(
        &self,
        args: &Args<'_>,
        object: usize,
        mut poll: impl FnMut() -> (i32, u32),
        at: &str,
    ) -> (i32, u32) {
        let Some(until) = args
            .arguments
            .contains_key("until")
            .then(|| args.narrow::<u32>("until", None))
        else {
            return poll();
        };
        let client = self.objects[object]
            .parent
            .map(|parent| self.objects[parent].handle);
        let mut total = 0u32;
        let start = std::time::Instant::now();
        loop {
            if let Some(client) = client {
                let _ = abi::client_poll(client);
            }
            let (status, delivered) = poll();
            if status != 0 {
                return (status, total);
            }
            total = total.checked_add(delivered).unwrap();
            if total >= until {
                return (0, total);
            }
            assert!(
                start.elapsed() < UNTIL_DEADLINE,
                "{at}: {total} of {until} after the deadline"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// Runs `offer` on `publication`. On a remote publication (its client is
    /// a provided one, `$remote_client` or `$archive_client`; FORMAT.md,
    /// Remote driver), or a `karyos:udp` one of a client of an embedded driver with its
    /// network on (FORMAT.md, Features, `embedded-network`), a
    /// `back_pressured`, `admin_action` or `not_connected` answer is
    /// retried, serving the client, until the offer answers anything else
    /// or 10 s pass: such a publication connects asynchronously, so its
    /// first offers may wait.
    fn offer_remote<T>(
        &self,
        publication: usize,
        mut offer: impl FnMut() -> (i32, T),
        at: &str,
    ) -> (i32, T) {
        // A provided client's, or a network publication of a client of an
        // embedded driver with its network on: those connect
        // asynchronously. Its IPC publications answer at once.
        let network = self.objects[publication].network;
        let client = self.objects[publication]
            .parent
            .filter(|parent| {
                let object = &self.objects[*parent];
                object.provided
                    || (network
                        && object
                            .parent
                            .is_some_and(|driver| self.objects[driver].networked))
            })
            .map(|parent| self.objects[parent].handle);
        let start = std::time::Instant::now();
        loop {
            let (status, value) = offer();
            let Some(client) = client else {
                return (status, value);
            };
            let waits = status != 0
                && matches!(
                    self.name(status, at).as_str(),
                    "back_pressured" | "admin_action" | "not_connected"
                );
            if !waits || start.elapsed() >= UNTIL_DEADLINE {
                return (status, value);
            }
            let _ = abi::client_poll(client);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// Runs `op` with `arguments` (variables already bound).
    pub fn op(&mut self, op: &str, arguments: &BTreeMap<String, Value>, at: &str) -> Answer {
        let args = Args { arguments, at };
        match op {
            "library.version" => {
                let (status, [major, minor, patch]) = abi::abi_version();
                if status != 0 {
                    return Answer::Status(self.name(status, at));
                }
                Answer::Ok(results([
                    ("major", Value::Integer(i128::from(major))),
                    ("minor", Value::Integer(i128::from(minor))),
                    ("patch", Value::Integer(i128::from(patch))),
                ]))
            }
            "clock.now" => {
                let domain = match args.text("domain").as_deref() {
                    Some("monotonic") => 0,
                    Some("tai") => 1,
                    other => panic!("{at}: `domain` is \"monotonic\" or \"tai\", not {other:?}"),
                };
                match abi::clock_now(domain) {
                    (0, Some(now)) => {
                        Answer::Ok(results([("now", Value::Integer(i128::from(now)))]))
                    }
                    (status, _) => Answer::Status(self.name(status, at)),
                }
            }
            "driver.create" | "driver.create_networked" => {
                let (status, driver) = if op == "driver.create" {
                    abi::driver_create()
                } else {
                    abi::driver_create_networked()
                };
                if status != 0 {
                    return Answer::Status(self.name(status, at));
                }
                let created = self.insert(Kind::Driver, driver, None);
                if let Value::Object(index) = created {
                    self.objects[index].networked = op == "driver.create_networked";
                }
                Answer::Ok(results([("driver", created)]))
            }
            "client.connect" => {
                // A client of the driver behind `dir`'s admission socket
                // (FORMAT.md, Incompatible driver), or of a provided driver.
                if let Some(dir) = args.text("dir") {
                    let dir =
                        CString::new(dir).unwrap_or_else(|_| panic!("{at}: `dir` holds a NUL"));
                    let (status, client, _) = abi::client_connect(&dir);
                    if status != 0 {
                        return Answer::Status(self.name(status, at));
                    }
                    let client = self.insert(Kind::Client, client, None);
                    return Answer::Ok(results([("client", client)]));
                }
                let driver = args.object("driver");
                if let Some(answer) = self.open(driver, Kind::Driver, at) {
                    return answer;
                }
                let (status, client) = abi::driver_connect(self.objects[driver].handle);
                if status != 0 {
                    return Answer::Status(self.name(status, at));
                }
                let client = self.insert(Kind::Client, client, Some(driver));
                Answer::Ok(results([("client", client)]))
            }
            "driver.add_stream" => {
                let driver = args.object("driver");
                if let Some(answer) = self.open(driver, Kind::Driver, at) {
                    return answer;
                }
                let (status, mut options) = abi::stream_options(args.narrow("stream_id", None));
                assert_eq!(status, 0, "{at}: karyos_stream_options_init");
                options.allow_unconnected =
                    args.narrow("allow_unconnected", Some(options.allow_unconnected));
                options.publication_mode =
                    args.narrow("publication_mode", Some(options.publication_mode));
                options.publishers = args.narrow("publishers", Some(options.publishers));
                options.spare_slots = args.narrow("spare_slots", Some(options.spare_slots));
                options.term_length = args.narrow("term_length", Some(options.term_length));
                options.conflation_keys =
                    args.narrow("conflation_keys", Some(options.conflation_keys));
                options.conflation_value_capacity = args.narrow(
                    "conflation_value_capacity",
                    Some(options.conflation_value_capacity),
                );
                options.conflation_journal_capacity = args.narrow(
                    "conflation_journal_capacity",
                    Some(options.conflation_journal_capacity),
                );
                let (status, _) = abi::driver_add_stream(self.objects[driver].handle, &options);
                self.plain(status, at)
            }
            "driver.start" => {
                let driver = args.object("driver");
                if let Some(answer) = self.open(driver, Kind::Driver, at) {
                    return answer;
                }
                // Left out, the ABI's declared default (FORMAT.md, Ops).
                let idle = match args.text("idle_strategy").as_deref() {
                    Some("busy_spin") => 0,
                    Some("yield") => 1,
                    Some("sleep") => 2,
                    Some("yield_then_sleep") | None => 3,
                    other => panic!("{at}: `idle_strategy` {other:?} is no idle strategy"),
                };
                let sleep = args.narrow("idle_sleep_ns", Some(0));
                self.plain(
                    abi::driver_start(self.objects[driver].handle, idle, sleep),
                    at,
                )
            }
            "driver.do_work" => {
                let driver = args.object("driver");
                if let Some(answer) = self.open(driver, Kind::Driver, at) {
                    return answer;
                }
                let (status, work) = abi::driver_do_work(self.objects[driver].handle);
                self.counted(status, "work", work, at)
            }
            "driver.subscribe_conflated" => {
                let driver = args.object("driver");
                if let Some(answer) = self.open(driver, Kind::Driver, at) {
                    return answer;
                }
                let (status, conflated) = abi::driver_subscribe_conflated(
                    self.objects[driver].handle,
                    args.narrow("stream_id", None),
                );
                if status != 0 {
                    return Answer::Status(self.name(status, at));
                }
                let conflated = self.insert(Kind::Conflated, conflated, Some(driver));
                Answer::Ok(results([("conflated", conflated)]))
            }
            "client.poll" => {
                let client = args.object("client");
                if let Some(answer) = self.open(client, Kind::Client, at) {
                    return answer;
                }
                let (status, served) = abi::client_poll(self.objects[client].handle);
                self.counted(status, "served", served, at)
            }
            "publication.add" | "publication.add_concurrent" => {
                let client = args.object("client");
                if let Some(answer) = self.open(client, Kind::Client, at) {
                    return answer;
                }
                let uri = args.uri();
                let (status, publication, _) = abi::client_add_publication_of(
                    self.objects[client].handle,
                    &uri,
                    args.narrow("stream_id", None),
                    u32::try_from(size_of::<abi::Detail>()).unwrap(),
                    op == "publication.add_concurrent",
                );
                if status != 0 {
                    return Answer::Status(self.name(status, at));
                }
                let publication = self.insert(Kind::Publication, publication, Some(client));
                if let Value::Object(index) = publication {
                    self.objects[index].network = uri.to_bytes().starts_with(b"karyos:udp");
                }
                Answer::Ok(results([("publication", publication)]))
            }
            "publication.offer" => {
                let publication = args.object("publication");
                if let Some(answer) = self.open(publication, Kind::Publication, at) {
                    return answer;
                }
                let handle = self.objects[publication].handle;
                let lane = args.narrow("lane", Some(0));
                let accepted_size = u32::try_from(size_of::<abi::Accepted>()).unwrap();
                let offer = || {
                    // A reserved value goes through the offer options: a
                    // conflated stream's key (FORMAT.md, Ops).
                    if args.arguments.contains_key("reserved_value") {
                        let (_, mut options) = abi::offer_options();
                        options.reserved_value = args.narrow("reserved_value", None);
                        abi::publication_offer_with(
                            handle,
                            lane,
                            &args.message(),
                            &options,
                            options.size,
                            accepted_size,
                        )
                    } else {
                        abi::publication_offer_on(handle, lane, &args.message(), accepted_size)
                    }
                };
                let (status, accepted) = self.offer_remote(publication, offer, at);
                self.accepted(status, &accepted, at)
            }
            "publication.offer_at" => {
                let publication = args.object("publication");
                if let Some(answer) = self.open(publication, Kind::Publication, at) {
                    return answer;
                }
                let handle = self.objects[publication].handle;
                let lane = args.narrow("lane", Some(0));
                let accepted_size = u32::try_from(size_of::<abi::Accepted>()).unwrap();
                let fixed = args
                    .arguments
                    .contains_key("tx_time")
                    .then(|| args.narrow::<u64>("tx_time", None));
                let delay = args.narrow::<u64>("delay_ns", Some(0));
                assert!(
                    fixed.is_none() || !args.arguments.contains_key("delay_ns"),
                    "{at}: `tx_time` or `delay_ns`, not both"
                );
                // A delay reads the monotonic clock at each attempt; the
                // last attempt's time is the answer's `tx_time`.
                let mut sent_at = 0;
                let offer = || {
                    let tx_time = fixed.unwrap_or_else(|| {
                        let (status, now) = abi::clock_now(0);
                        assert_eq!(status, 0, "{at}: karyos_clock_now");
                        now.unwrap().checked_add(delay).unwrap()
                    });
                    sent_at = tx_time;
                    abi::publication_offer_at(handle, lane, &args.message(), tx_time, accepted_size)
                };
                let (status, accepted) = self.offer_remote(publication, offer, at);
                let mut answer = self.accepted(status, &accepted, at);
                if let Answer::Ok(results) = &mut answer {
                    results.insert("tx_time".to_owned(), Value::Integer(i128::from(sent_at)));
                }
                answer
            }
            "publication.publish_claimed" => {
                let publication = args.object("publication");
                if let Some(answer) = self.open(publication, Kind::Publication, at) {
                    return answer;
                }
                let message = args.message();
                let (status, claim) = abi::publication_claim_filled(
                    self.objects[publication].handle,
                    args.narrow("lane", Some(0)),
                    u32::try_from(message.len()).unwrap(),
                    &message,
                );
                if status != 0 {
                    return Answer::Status(self.name(status, at));
                }
                let (status, accepted) =
                    abi::claim_commit(claim, u32::try_from(size_of::<abi::Accepted>()).unwrap());
                let answer = self.accepted(status, &accepted, at);
                // One attempt: a claim a retryable status kept staged is
                // aborted before the status returns (BIND-S3).
                if let Answer::Status(name) = &answer
                    && RETRYABLE.contains(&name.as_str())
                {
                    assert_eq!(
                        abi::claim_abort(claim),
                        0,
                        "{at}: the abort of a kept claim"
                    );
                }
                answer
            }
            "publication.claim" => {
                let publication = args.object("publication");
                if let Some(answer) = self.open(publication, Kind::Publication, at) {
                    return answer;
                }
                let (status, claim) = abi::publication_claim(
                    self.objects[publication].handle,
                    args.narrow("lane", Some(0)),
                    args.narrow("length", None),
                );
                if status != 0 {
                    return Answer::Status(self.name(status, at));
                }
                let claim = self.insert(Kind::Claim, claim, Some(publication));
                Answer::Ok(results([("claim", claim)]))
            }
            "claim.commit" => {
                let claim = args.object("claim");
                if let Some(answer) = self.open(claim, Kind::Claim, at) {
                    return answer;
                }
                let (status, accepted) = abi::claim_commit(
                    self.objects[claim].handle,
                    u32::try_from(size_of::<abi::Accepted>()).unwrap(),
                );
                let answer = self.accepted(status, &accepted, at);
                // Only a retryable status keeps the claim staged.
                let kept =
                    matches!(&answer, Answer::Status(name) if RETRYABLE.contains(&name.as_str()));
                if !kept {
                    self.objects[claim].closed = true;
                }
                answer
            }
            "publication.poll_outcomes" => {
                let publication = args.object("publication");
                if let Some(answer) = self.open(publication, Kind::Publication, at) {
                    return answer;
                }
                let handle = self.objects[publication].handle;
                let (lane, limit) = (args.narrow("lane", Some(0)), args.narrow("limit", Some(1)));
                let poll = || {
                    let (status, delivered, records) =
                        abi::publication_poll_outcomes(handle, lane, limit);
                    assert_eq!(usize::try_from(delivered).unwrap(), records.len(), "{at}");
                    (status, delivered)
                };
                let (status, delivered) = self.poll_until(&args, publication, poll, at);
                self.counted(status, "delivered", delivered, at)
            }
            "subscription.add" => {
                let client = args.object("client");
                if let Some(answer) = self.open(client, Kind::Client, at) {
                    return answer;
                }
                let (status, mut options) = abi::subscription_options();
                assert_eq!(status, 0, "{at}: karyos_subscription_options_init");
                options.role = args.narrow("role", Some(options.role));
                options.rejoin = args.narrow("rejoin", Some(options.rejoin));
                let (status, subscription) = abi::client_add_subscription_with(
                    self.objects[client].handle,
                    &args.uri(),
                    args.narrow("stream_id", None),
                    &options,
                    u32::try_from(size_of::<abi::SubscriptionOptions>()).unwrap(),
                );
                if status != 0 {
                    return Answer::Status(self.name(status, at));
                }
                let subscription = self.insert(Kind::Subscription, subscription, Some(client));
                Answer::Ok(results([("subscription", subscription)]))
            }
            "subscription.poll" => {
                let subscription = args.object("subscription");
                if let Some(answer) = self.open(subscription, Kind::Subscription, at) {
                    return answer;
                }
                let handle = self.objects[subscription].handle;
                let limit = args.narrow("limit", Some(1));
                // With `until`, polled until that many arrived (FORMAT.md,
                // Remote driver); the last message is the last poll's.
                let mut last: Option<Vec<u8>> = None;
                let (status, delivered) = self.poll_until(
                    &args,
                    subscription,
                    || {
                        let (status, delivered, messages, _) =
                            abi::subscription_poll(handle, limit, abi::OnMessage::Keep);
                        assert_eq!(usize::try_from(delivered).unwrap(), messages.len(), "{at}");
                        if let Some(message) = messages.last() {
                            last = Some(message.clone());
                        }
                        (status, delivered)
                    },
                    at,
                );
                // `not_before`: a delivery read before that monotonic time
                // fails the scenario (FORMAT.md, Remote driver).
                if delivered > 0 && args.arguments.contains_key("not_before") {
                    let not_before = args.narrow::<u64>("not_before", None);
                    let (status, now) = abi::clock_now(0);
                    assert_eq!(status, 0, "{at}: karyos_clock_now");
                    assert!(
                        now.unwrap() >= not_before,
                        "{at}: delivered at {now:?}, before its time {not_before}"
                    );
                }
                let mut answer = self.counted(status, "delivered", delivered, at);
                if let (Answer::Ok(results), Some(last)) = (&mut answer, last.as_ref()) {
                    let text = String::from_utf8(last.clone())
                        .unwrap_or_else(|_| panic!("{at}: a message that is not UTF-8"));
                    results.insert("last".to_owned(), Value::Text(text));
                }
                answer
            }
            "conflated.add" => {
                let client = args.object("client");
                if let Some(answer) = self.open(client, Kind::Client, at) {
                    return answer;
                }
                let (status, conflated) = abi::client_add_conflated_subscription(
                    self.objects[client].handle,
                    &args.uri(),
                    args.narrow("stream_id", None),
                );
                if status != 0 {
                    return Answer::Status(self.name(status, at));
                }
                let conflated = self.insert(Kind::Conflated, conflated, Some(client));
                Answer::Ok(results([("conflated", conflated)]))
            }
            "conflated.poll" => {
                let conflated = args.object("conflated");
                if let Some(answer) = self.open(conflated, Kind::Conflated, at) {
                    return answer;
                }
                let handle = self.objects[conflated].handle;
                let key_budget = args.narrow("key_budget", Some(1));
                let poll = || {
                    let (status, delivered, counted) = abi::conflated_poll(handle, key_budget);
                    assert_eq!(delivered, counted, "{at}: the count is the handler's calls");
                    (status, delivered)
                };
                let (status, delivered) = self.poll_until(&args, conflated, poll, at);
                self.counted(status, "delivered", delivered, at)
            }
            "archive.connect" => {
                let client = args.object("client");
                if let Some(answer) = self.open(client, Kind::Client, at) {
                    return answer;
                }
                let client_id =
                    NEXT_ARCHIVE_ID.fetch_add(100, std::sync::atomic::Ordering::Relaxed);
                let options = abi::ArchiveOptions {
                    size: u32::try_from(size_of::<abi::ArchiveOptions>()).unwrap(),
                    reserved: 0,
                    requests: ARCHIVE_REQUESTS,
                    responses: ARCHIVE_RESPONSES,
                    client_id,
                    deadline_ns: u64::try_from(ARCHIVE_DEADLINE.as_nanos()).unwrap(),
                };
                let (status, archive) = abi::archive_connect(self.objects[client].handle, &options);
                if status != 0 {
                    return Answer::Status(self.name(status, at));
                }
                let archive = self.insert(Kind::Archive, archive, Some(client));
                Answer::Ok(results([("archive", archive)]))
            }
            "archive.replay" => {
                let archive = args.object("archive");
                if let Some(answer) = self.open(archive, Kind::Archive, at) {
                    return answer;
                }
                let (status, mut options) = abi::replay_options();
                assert_eq!(status, 0, "{at}: karyos_replay_options_init");
                options.recording_id = args.narrow("recording", None);
                options.target_stream_id = args.narrow("target_stream_id", None);
                options.position = args.narrow("position", Some(options.position));
                options.length = args.narrow("length", Some(options.length));
                options.rate = match args.text("rate").as_deref() {
                    None | Some("full") => 1,
                    Some("as_recorded") => 2,
                    Some("scaled") => 3,
                    other => panic!("{at}: `rate` {other:?} is no replay rate"),
                };
                options.scale_ppm = args.narrow("scale_ppm", Some(0));
                let (status, replay_id, session_id, code) =
                    abi::archive_replay(self.objects[archive].handle, &options);
                if status != 0 {
                    return self.archive_failure(status, code, at);
                }
                self.replays.push((archive, replay_id));
                Answer::Ok(results([
                    ("replay", Value::Integer(i128::from(replay_id))),
                    ("session", Value::Integer(i128::from(session_id))),
                ]))
            }
            "archive.stop_replay" => {
                let archive = args.object("archive");
                if let Some(answer) = self.open(archive, Kind::Archive, at) {
                    return answer;
                }
                let replay_id: u64 = args.narrow("replay", None);
                let (status, code) =
                    abi::archive_stop_replay(self.objects[archive].handle, replay_id);
                if status != 0 {
                    return self.archive_failure(status, code, at);
                }
                self.replays
                    .retain(|started| *started != (archive, replay_id));
                Answer::Ok(BTreeMap::new())
            }
            "replay.subscribe" => {
                let client = args.object("client");
                if let Some(answer) = self.open(client, Kind::Client, at) {
                    return answer;
                }
                let handle = self.objects[client].handle;
                let (stream_id, session_id) =
                    (args.narrow("stream_id", None), args.narrow("session", None));
                // Serves the client until the target's grant, up to the
                // suite's deadline (FORMAT.md, Archive replays).
                let start = std::time::Instant::now();
                loop {
                    let _ = abi::client_poll(handle);
                    let (status, subscription) =
                        abi::client_add_replay_subscription(handle, stream_id, session_id);
                    match status {
                        0 => {
                            let subscription =
                                self.insert(Kind::Subscription, subscription, Some(client));
                            return Answer::Ok(results([("subscription", subscription)]));
                        }
                        status if self.name(status, at) == "not_connected" => {
                            if start.elapsed() >= ARCHIVE_DEADLINE {
                                return Answer::Status("timeout".to_owned());
                            }
                            std::thread::yield_now();
                        }
                        status => return Answer::Status(self.name(status, at)),
                    }
                }
            }
            "subscription.poll_to_end" => {
                let subscription = args.object("subscription");
                if let Some(answer) = self.open(subscription, Kind::Subscription, at) {
                    return answer;
                }
                let handle = self.objects[subscription].handle;
                let client = self.objects[subscription]
                    .parent
                    .map(|parent| self.objects[parent].handle);
                let limit = args.narrow("limit", Some(16));
                // Polls, serving its client, until the subscription ends.
                let (mut delivered, mut last) = (0u32, None);
                let start = std::time::Instant::now();
                loop {
                    if let Some(client) = client {
                        let _ = abi::client_poll(client);
                    }
                    let (status, count, messages, _) =
                        abi::subscription_poll(handle, limit, abi::OnMessage::Keep);
                    delivered = delivered.checked_add(count).unwrap();
                    if let Some(message) = messages.last() {
                        last = Some(
                            String::from_utf8(message.clone())
                                .unwrap_or_else(|_| panic!("{at}: a message that is not UTF-8")),
                        );
                    }
                    match self.name_or_ok(status, at).as_deref() {
                        None => {}
                        Some("closed" | "closed_by_overrun") => break,
                        Some(other) => return Answer::Status(other.to_owned()),
                    }
                    if start.elapsed() >= END_DEADLINE {
                        return Answer::Status("timeout".to_owned());
                    }
                    std::thread::yield_now();
                }
                let mut answer = results([("delivered", Value::Integer(i128::from(delivered)))]);
                if let Some(last) = last {
                    answer.insert("last".to_owned(), Value::Text(last));
                }
                Answer::Ok(answer)
            }
            "subscription.end" => {
                let subscription = args.object("subscription");
                assert_eq!(self.objects[subscription].kind, Kind::Subscription, "{at}");
                if self.is_closed(subscription) {
                    return Answer::Status("closed".to_owned());
                }
                let (status, end) = abi::subscription_end_state(self.objects[subscription].handle);
                if status != 0 {
                    return Answer::Status(self.name(status, at));
                }
                let reason = match end.reason {
                    0 => "none",
                    1 => "end_of_stream",
                    2 => "image_retired",
                    3 => "stream_removed",
                    4 => "revoked",
                    5 => "closed_by_overrun",
                    _ => "other",
                };
                Answer::Ok(results([
                    ("reason", Value::Text(reason.to_owned())),
                    ("position", Value::Integer(i128::from(end.position))),
                    ("seal_code", Value::Integer(i128::from(end.seal_code))),
                ]))
            }
            "driver.close" | "client.close" | "publication.close" | "subscription.close"
            | "conflated.close" | "claim.abort" | "archive.close" => {
                let (name, kind) = match op {
                    "driver.close" => ("driver", Kind::Driver),
                    "client.close" => ("client", Kind::Client),
                    "publication.close" => ("publication", Kind::Publication),
                    "subscription.close" => ("subscription", Kind::Subscription),
                    "conflated.close" => ("conflated", Kind::Conflated),
                    "archive.close" => ("archive", Kind::Archive),
                    _ => ("claim", Kind::Claim),
                };
                let index = args.object(name);
                self.close(index, kind, op == "claim.abort", at)
            }
            other => panic!("{at}: this runner does not know op `{other}`"),
        }
    }

    /// `None` when the object of `kind` is open; `closed` when it or a
    /// parent is closed.
    fn open(&self, index: usize, kind: Kind, at: &str) -> Option<Answer> {
        assert_eq!(self.objects[index].kind, kind, "{at}: not a {kind:?}");
        self.is_closed(index)
            .then(|| Answer::Status("closed".to_owned()))
    }

    /// A close: `ok` once closed, by its own close or a parent's; a
    /// refused close (`busy`, `reentrant`) closes nothing. An abort is a
    /// claim's close, but a claim already ended answers `closed`, as a
    /// commit after it does.
    fn close(&mut self, index: usize, kind: Kind, abort: bool, at: &str) -> Answer {
        assert_eq!(self.objects[index].kind, kind, "{at}: not a {kind:?}");
        if self.is_closed(index) {
            return if abort {
                Answer::Status("closed".to_owned())
            } else {
                Answer::Ok(BTreeMap::new())
            };
        }
        // A provided object stays open for the runner: its close ends its
        // use in this scenario only.
        if self.objects[index].provided {
            self.objects[index].closed = true;
            return Answer::Ok(BTreeMap::new());
        }
        let handle = self.objects[index].handle;
        let status = match kind {
            Kind::Driver => abi::driver_close(handle),
            Kind::Client => abi::client_close(handle),
            Kind::Publication => abi::publication_close(handle),
            Kind::Subscription => abi::subscription_close(handle),
            Kind::Conflated => abi::conflated_close(handle),
            Kind::Claim => abi::claim_abort(handle),
            Kind::Archive => {
                // Its replays are stopped first: a close leaves them
                // running (FORMAT.md, Archive replays).
                self.stop_replays_of(index);
                abi::archive_close(handle)
            }
        };
        if status == 0 {
            self.objects[index].closed = true;
        }
        self.plain(status, at)
    }

    /// `None` for `KARYOS_OK`, else the status's name.
    fn name_or_ok(&self, code: i32, at: &str) -> Option<String> {
        (code != 0).then(|| self.name(code, at))
    }

    /// Stops the replays the scenario started on Archive connection
    /// `archive` and did not see stop.
    fn stop_replays_of(&mut self, archive: usize) {
        let handle = self.objects[archive].handle;
        self.replays.retain(|(started, replay_id)| {
            if *started == archive {
                let _ = abi::archive_stop_replay(handle, *replay_id);
                false
            } else {
                true
            }
        });
    }

    /// An Archive call's failure: a refusal carries the Archive's response
    /// code (FORMAT.md, Outcomes).
    fn archive_failure(&self, status: i32, code: u64, at: &str) -> Answer {
        let name = self.name(status, at);
        if name == "refused" {
            Answer::StatusWith(name, results([("code", Value::Integer(i128::from(code)))]))
        } else {
            Answer::Status(name)
        }
    }

    fn counted(&self, status: i32, name: &str, count: u32, at: &str) -> Answer {
        if status != 0 {
            return Answer::Status(self.name(status, at));
        }
        Answer::Ok(results([(name, Value::Integer(i128::from(count)))]))
    }

    fn accepted(
        &self,
        status: i32,
        accepted: &abi::SizedStruct<abi::Accepted>,
        at: &str,
    ) -> Answer {
        if status != 0 {
            return Answer::Status(self.name(status, at));
        }
        let (lane, position) = abi::accepted_fields(accepted)
            .unwrap_or_else(|| panic!("{at}: an accepted offer wrote no position"));
        Answer::Ok(results([
            ("lane", Value::Integer(i128::from(lane))),
            ("position", Value::Integer(i128::from(position))),
        ]))
    }
}

fn results<const N: usize>(pairs: [(&str, Value); N]) -> BTreeMap<String, Value> {
    pairs
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect()
}

/// An op's bound arguments; the parser has checked their names.
struct Args<'a> {
    arguments: &'a BTreeMap<String, Value>,
    at: &'a str,
}

impl Args<'_> {
    fn object(&self, name: &str) -> usize {
        match self.arguments.get(name) {
            Some(Value::Object(index)) => *index,
            other => panic!("{}: `{name}` must be an object, got {other:?}", self.at),
        }
    }

    /// An integer argument that fits `T`, or `default` (`None`: required).
    fn narrow<T: TryFrom<i128>>(&self, name: &str, default: Option<T>) -> T {
        match self.arguments.get(name) {
            None => default.unwrap_or_else(|| panic!("{}: `{name}` is required", self.at)),
            Some(Value::Integer(value)) => T::try_from(*value)
                .unwrap_or_else(|_| panic!("{}: `{name}` does not fit its type", self.at)),
            Some(other) => panic!("{}: `{name}` must be an integer, got {other:?}", self.at),
        }
    }

    fn text(&self, name: &str) -> Option<String> {
        match self.arguments.get(name) {
            None => None,
            Some(Value::Text(text)) => Some(text.clone()),
            Some(other) => panic!("{}: `{name}` must be a string, got {other:?}", self.at),
        }
    }

    fn uri(&self) -> CString {
        CString::new(self.text("uri").unwrap_or_else(|| "karyos:ipc".to_owned()))
            .unwrap_or_else(|_| panic!("{}: `uri` holds a NUL", self.at))
    }

    /// `payload`'s bytes, or `length` zero bytes; one of them.
    fn message(&self) -> Vec<u8> {
        match (self.text("payload"), self.arguments.contains_key("length")) {
            (Some(payload), false) => payload.into_bytes(),
            (None, true) => vec![0; self.narrow::<usize>("length", None)],
            _ => panic!("{}: `payload` or `length`, one of them", self.at),
        }
    }
}
