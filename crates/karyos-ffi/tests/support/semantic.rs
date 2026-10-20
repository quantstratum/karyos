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
}

/// An object a scenario holds: its C handle, its parent and whether its
/// own close succeeded.
#[derive(Debug)]
struct Object {
    kind: Kind,
    handle: u64,
    parent: Option<usize>,
    closed: bool,
}

/// The answer of an op: `ok` with its results, or a status name.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    Ok(BTreeMap<String, Value>),
    Status(String),
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
        }
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
        for index in (0..self.objects.len()).rev() {
            if self.is_closed(index) {
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
            "driver.create" => {
                let (status, driver) = abi::driver_create();
                if status != 0 {
                    return Answer::Status(self.name(status, at));
                }
                Answer::Ok(results([(
                    "driver",
                    self.insert(Kind::Driver, driver, None),
                )]))
            }
            "client.connect" => {
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
                Answer::Ok(results([("publication", publication)]))
            }
            "publication.offer" => {
                let publication = args.object("publication");
                if let Some(answer) = self.open(publication, Kind::Publication, at) {
                    return answer;
                }
                let (status, accepted) = abi::publication_offer_on(
                    self.objects[publication].handle,
                    args.narrow("lane", Some(0)),
                    &args.message(),
                    u32::try_from(size_of::<abi::Accepted>()).unwrap(),
                );
                self.accepted(status, &accepted, at)
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
                let (status, delivered, records) = abi::publication_poll_outcomes(
                    self.objects[publication].handle,
                    args.narrow("lane", Some(0)),
                    args.narrow("limit", Some(1)),
                );
                assert_eq!(usize::try_from(delivered).unwrap(), records.len(), "{at}");
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
                let (status, delivered, messages, _) = abi::subscription_poll(
                    self.objects[subscription].handle,
                    args.narrow("limit", Some(1)),
                    abi::OnMessage::Keep,
                );
                assert_eq!(usize::try_from(delivered).unwrap(), messages.len(), "{at}");
                let mut answer = self.counted(status, "delivered", delivered, at);
                if let (Answer::Ok(results), Some(last)) = (&mut answer, messages.last()) {
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
                let (status, delivered, counted) = abi::conflated_poll(
                    self.objects[conflated].handle,
                    args.narrow("key_budget", Some(1)),
                );
                assert_eq!(delivered, counted, "{at}: the count is the handler's calls");
                self.counted(status, "delivered", delivered, at)
            }
            "driver.close" | "client.close" | "publication.close" | "subscription.close"
            | "conflated.close" | "claim.abort" => {
                let (name, kind) = match op {
                    "driver.close" => ("driver", Kind::Driver),
                    "client.close" => ("client", Kind::Client),
                    "publication.close" => ("publication", Kind::Publication),
                    "subscription.close" => ("subscription", Kind::Subscription),
                    "conflated.close" => ("conflated", Kind::Conflated),
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
        let handle = self.objects[index].handle;
        let status = match kind {
            Kind::Driver => abi::driver_close(handle),
            Kind::Client => abi::client_close(handle),
            Kind::Publication => abi::publication_close(handle),
            Kind::Subscription => abi::subscription_close(handle),
            Kind::Conflated => abi::conflated_close(handle),
            Kind::Claim => abi::claim_abort(handle),
        };
        if status == 0 {
            self.objects[index].closed = true;
        }
        self.plain(status, at)
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
