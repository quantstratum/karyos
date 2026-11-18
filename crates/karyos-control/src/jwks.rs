// SPDX-License-Identifier: Apache-2.0

//! The issuer's key set, fetched and kept fresh (the JWKS retrieval
//! record, quantstratum-docs:
//! karyos/reviews/dependency-admission-jwks-retrieval.md, conditions 1 to
//! 6, as the owner decided them: no stale-key trust, no grace).
//!
//! - **Where.** The configured issuer's discovery document,
//!   `{issuer}/.well-known/openid-configuration`, whose `issuer` must
//!   equal the configured one byte for byte and whose `jwks_uri` must be
//!   `https` on the issuer's host or a configured one. Never a URL from a
//!   token.
//! - **How.** `hyper`'s HTTP/1.1 client over TLS 1.3 with the configured
//!   anchors only; no redirect followed; [`FETCH_DEADLINE`] end to end;
//!   at most [`MAX_BODY`] bytes and [`jwt::MAX_KEYS`] keys; a duplicate
//!   `kid` refuses the set.
//! - **Freshness (RFC 9111 §4.2, §5.2).** A set's lifetime is its
//!   `max-age`, else `Expires` minus `Date`, else zero; `no-store` and
//!   `no-cache` make it zero; its age on receipt is the larger of `Age`
//!   and the time since its `Date` (§4.2.3), so an old `Date` or an
//!   `Expires` already past is stale on receipt. The lifetime
//!   is never raised. A set past it is never used, including one already
//!   past it on receipt (its `Age` consumed the lifetime): every token that
//!   needs it is refused with [`KeysError::Unavailable`] (`503`) until a fetch
//!   succeeds.
//! - **One fetch at a time.** One [`Jwks`] per configured issuer holds at
//!   most one fetch in flight and one budget: after a fetch, the next may
//!   start [`Budget::floor`] later at the earliest, doubled after each
//!   failure up to [`Budget::cap`]. The budget bounds polling only, never
//!   trust: a set past its lifetime stays unusable while the budget waits.
//!   A request waits for a fetch in flight [`FETCH_DEADLINE`] at most, and
//!   the component's connection limit bounds how many wait.
//! - **Failures.** A fetch that fails (unreachable, bad TLS, a status but
//!   200, a wrong issuer, bad JSON, a bound passed) changes nothing of the
//!   last good set and does not reset its age.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use hyper::body::{Body, Incoming};
use hyper::{Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use tokio_rustls::TlsConnector;

use crate::jwt::{self, KeySet};
use crate::server::Reply;

/// The time one fetch may take, connect to last body byte.
pub const FETCH_DEADLINE: Duration = Duration::from_secs(5);
/// The largest discovery document or key set, in bytes.
pub const MAX_BODY: usize = 64 << 10;
/// How often a waiting request looks at the fetch in flight.
const WAIT_STEP: Duration = Duration::from_millis(5);

/// How often the fetcher may poll: availability only, never trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Budget {
    /// The least time between two fetches (decided default: 30 s).
    pub floor: Duration,
    /// The most time between two fetches after failures (decided default:
    /// 5 minutes).
    pub cap: Duration,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            floor: Duration::from_secs(30),
            cap: Duration::from_secs(300),
        }
    }
}

impl Budget {
    /// A budget of `floor` and `cap` (at least `floor`), each at most
    /// [`Budget::MAX`], so a wait is always a representable deadline.
    #[must_use]
    pub fn new(floor: Duration, cap: Duration) -> Self {
        let floor = floor.min(Self::MAX);
        Self {
            floor,
            cap: cap.min(Self::MAX).max(floor),
        }
    }

    /// The longest floor or cap: a day.
    pub const MAX: Duration = Duration::from_secs(24 * 60 * 60);

    /// The wait before the next fetch after `failures` failures in a row.
    /// When the next fetch may start, `failures` failures in a row after
    /// `now`. A wait past what `Instant` holds (none, with [`Budget::MAX`])
    /// is the latest it holds.
    fn next(&self, now: Instant, failures: u32) -> Instant {
        let wait = self.wait(failures);
        now.checked_add(wait)
            .or_else(|| now.checked_add(Self::MAX))
            .unwrap_or(now)
    }

    fn wait(&self, failures: u32) -> Duration {
        let factor = 1u32.checked_shl(failures.min(16)).unwrap_or(u32::MAX);
        self.floor.saturating_mul(factor).min(self.cap)
    }
}

/// Why no key set can verify a token now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeysError {
    /// No set inside its lifetime, and none could be fetched now: the
    /// issuer or its key set endpoint failed, or the budget forbids a
    /// fetch. Answered `503`; never a grant.
    #[error("token keys unavailable")]
    Unavailable,
}

/// The configured issuer.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Issuer {
    /// Its identifier, an `https` URL, compared byte for byte.
    pub issuer: String,
    /// The anchors its TLS server certificates chain to.
    pub anchors: Vec<CertificateDer<'static>>,
    /// Another host its `jwks_uri` may be on, besides the issuer's.
    pub jwks_host: Option<String>,
    /// The fetch budget.
    pub budget: Budget,
}

impl Issuer {
    /// Issuer `issuer`, trusted through `anchors`.
    #[must_use]
    pub fn new(issuer: &str, anchors: Vec<CertificateDer<'static>>) -> Self {
        Self {
            issuer: issuer.to_owned(),
            anchors,
            jwks_host: None,
            budget: Budget::default(),
        }
    }

    /// The same, with `budget`.
    #[must_use]
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = budget;
        self
    }

    /// The same, allowing a `jwks_uri` on `host`.
    #[must_use]
    pub fn with_jwks_host(mut self, host: &str) -> Self {
        self.jwks_host = Some(host.to_owned());
        self
    }
}

/// A set and when it stops being fresh.
#[derive(Debug, Clone)]
struct Fresh {
    set: Arc<KeySet>,
    /// When the set's age reaches its lifetime: its fetch time, less its
    /// `Age`, plus its lifetime.
    until: Instant,
}

/// The fetcher's state.
#[derive(Debug)]
struct State {
    last: Option<Fresh>,
    jwks_uri: Option<Uri>,
    in_flight: bool,
    /// Counts finished fetches, so that a waiter knows its fetch ended.
    generation: u64,
    /// The set the last finished fetch got, if it succeeded: a waiter on
    /// that fetch may use it even when its lifetime is zero.
    /// With the deadline past which no one may use it, `None` for a zero
    /// lifetime (that fetch's requests only).
    fetched: Option<(u64, Arc<KeySet>, Option<Instant>)>,
    next_allowed: Option<Instant>,
    failures: u32,
}

/// One configured issuer's key sets.
#[derive(Debug)]
pub struct Jwks {
    issuer: Issuer,
    tls: Arc<ClientConfig>,
    state: Mutex<State>,
}

/// Why a fetch failed (it changes nothing; see the module).
#[derive(Debug, thiserror::Error)]
enum FetchError {
    #[error("unreachable: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(#[from] hyper::Error),
    #[error("not a fetchable URL")]
    Url,
    #[error("status {0}")]
    Status(StatusCode),
    #[error("too large or cut short")]
    Body,
    #[error("deadline passed")]
    Deadline,
    #[error("discovery document refused")]
    Discovery,
    #[error(transparent)]
    Keys(#[from] jwt::KeySetError),
}

impl Jwks {
    /// The key sets of `issuer`.
    ///
    /// # Errors
    ///
    /// `rustls`'s, for an anchor it refuses.
    pub fn new(issuer: Issuer) -> Result<Self, rustls::Error> {
        let mut roots = RootCertStore::empty();
        for anchor in &issuer.anchors {
            roots.add(anchor.clone())?;
        }
        let mut tls =
            ClientConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(roots)
                .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            issuer,
            tls: Arc::new(tls),
            state: Mutex::new(State {
                last: None,
                jwks_uri: None,
                in_flight: false,
                generation: 0,
                fetched: None,
                next_allowed: None,
                failures: 0,
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A set that may verify a token of key `kid` now: the current one if
    /// it is fresh and holds `kid`, else the one a fetch gets, if the
    /// budget allows one or one is in flight.
    ///
    /// # Errors
    ///
    /// [`KeysError::Unavailable`]: no fresh set, and none fetched.
    pub async fn keys_for(&self, kid: &str) -> Result<Arc<KeySet>, KeysError> {
        let waiting_on = {
            let mut state = self.lock();
            let now = Instant::now();
            if let Some(fresh) = state
                .last
                .as_ref()
                .filter(|fresh| now < fresh.until && fresh.set.contains(kid))
            {
                return Ok(Arc::clone(&fresh.set));
            }
            if state.in_flight {
                Some(state.generation)
            } else if state.next_allowed.is_some_and(|next| now < next) {
                return Err(KeysError::Unavailable);
            } else {
                state.in_flight = true;
                None
            }
        };
        match waiting_on {
            Some(generation) => self.wait(generation).await,
            None => self.fetch().await,
        }
    }

    /// Waits for the fetch in flight past `generation` to end.
    async fn wait(&self, generation: u64) -> Result<Arc<KeySet>, KeysError> {
        let start = Instant::now();
        while start.elapsed() < FETCH_DEADLINE.saturating_add(WAIT_STEP) {
            tokio::time::sleep(WAIT_STEP).await;
            let state = self.lock();
            if state.generation != generation {
                return match &state.fetched {
                    Some((fetched, set, until))
                        if *fetched == state.generation
                            && until.is_none_or(|until| Instant::now() < until) =>
                    {
                        Ok(Arc::clone(set))
                    }
                    _ => Err(KeysError::Unavailable),
                };
            }
        }
        Err(KeysError::Unavailable)
    }

    /// Makes the one fetch in flight and records how it ended. If the
    /// request that started it is cancelled before it ends, the fetch ends
    /// as a failure all the same ([`InFlight`]), so a later request may
    /// start the next one.
    async fn fetch(&self) -> Result<Arc<KeySet>, KeysError> {
        let guard = InFlight(Some(self));
        let jwks_uri = self.lock().jwks_uri.clone();
        let started = Instant::now();
        let result = tokio::time::timeout(FETCH_DEADLINE, self.fetch_set(jwks_uri))
            .await
            .unwrap_or(Err(FetchError::Deadline));
        guard.disarm();
        let mut state = self.lock();
        state.in_flight = false;
        state.generation = state.generation.wrapping_add(1);
        let now = Instant::now();
        match result {
            Ok((uri, set, freshness)) => {
                // Its age counts from the request, less what caches held.
                let born = started.checked_sub(freshness.age).unwrap_or(started);
                let until = born.checked_add(freshness.lifetime).unwrap_or(born);
                let positive = !freshness.lifetime.is_zero();
                // Stale on receipt, or its positive lifetime ran out while
                // the body was read: never used, not even by the request
                // that fetched it. Only an origin response of zero
                // lifetime, not explicitly expired, serves that one
                // request and its waiters.
                if freshness.stale_on_receipt() || (positive && now >= until) {
                    state.failures = state.failures.saturating_add(1);
                    let failures = state.failures;
                    state.next_allowed = Some(self.issuer.budget.next(now, failures));
                    state.fetched = None;
                    return Err(KeysError::Unavailable);
                }
                let set = Arc::new(set);
                state.jwks_uri = Some(uri);
                state.failures = 0;
                state.next_allowed = Some(self.issuer.budget.next(now, 0));
                state.last = Some(Fresh {
                    set: Arc::clone(&set),
                    until,
                });
                state.fetched = Some((
                    state.generation,
                    Arc::clone(&set),
                    positive.then_some(until),
                ));
                Ok(set)
            }
            Err(_) => {
                state.failures = state.failures.saturating_add(1);
                let failures = state.failures;
                state.next_allowed = Some(self.issuer.budget.next(now, failures));
                state.fetched = None;
                Err(KeysError::Unavailable)
            }
        }
    }

    /// Ends the fetch in flight as a failure: its waiters get `503`, the
    /// budget counts it, and the next request may start another.
    fn abandon(&self) {
        let mut state = self.lock();
        state.in_flight = false;
        state.generation = state.generation.wrapping_add(1);
        state.failures = state.failures.saturating_add(1);
        let failures = state.failures;
        state.next_allowed = Some(self.issuer.budget.next(Instant::now(), failures));
        state.fetched = None;
    }

    /// The discovery document's `jwks_uri` (when not known yet), then the
    /// key set and its freshness.
    async fn fetch_set(
        &self,
        jwks_uri: Option<Uri>,
    ) -> Result<(Uri, KeySet, Freshness), FetchError> {
        let jwks_uri = match jwks_uri {
            Some(uri) => uri,
            None => self.discover().await?,
        };
        let (body, freshness) = self.get(&jwks_uri).await?;
        Ok((jwks_uri, KeySet::parse(&body)?, freshness))
    }

    async fn discover(&self) -> Result<Uri, FetchError> {
        let issuer: Uri = self.issuer.issuer.parse().map_err(|_| FetchError::Url)?;
        let base = self.issuer.issuer.trim_end_matches('/');
        let url: Uri = format!("{base}/.well-known/openid-configuration")
            .parse()
            .map_err(|_| FetchError::Url)?;
        let (body, _) = self.get(&url).await?;
        let document: Value = serde_json::from_slice(&body).map_err(|_| FetchError::Discovery)?;
        if document.get("issuer").and_then(Value::as_str) != Some(self.issuer.issuer.as_str()) {
            return Err(FetchError::Discovery);
        }
        let jwks_uri: Uri = document
            .get("jwks_uri")
            .and_then(Value::as_str)
            .ok_or(FetchError::Discovery)?
            .parse()
            .map_err(|_| FetchError::Discovery)?;
        let host_allowed = jwks_uri.host().is_some_and(|host| {
            Some(host) == issuer.host() || self.issuer.jwks_host.as_deref() == Some(host)
        });
        if jwks_uri.scheme_str() != Some("https") || !host_allowed {
            return Err(FetchError::Discovery);
        }
        Ok(jwks_uri)
    }

    /// One `GET` of `url`: its body, at most [`MAX_BODY`] bytes, if the
    /// answer is `200`, and its freshness.
    async fn get(&self, url: &Uri) -> Result<(Vec<u8>, Freshness), FetchError> {
        let (Some("https"), Some(host)) = (url.scheme_str(), url.host()) else {
            return Err(FetchError::Url);
        };
        if url
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        {
            return Err(FetchError::Url);
        }
        let port = url.port_u16().unwrap_or(443);
        let tcp = tokio::net::TcpStream::connect((host, port)).await?;
        let name = ServerName::try_from(host.to_owned()).map_err(|_| FetchError::Url)?;
        let tls = TlsConnector::from(Arc::clone(&self.tls))
            .connect(name, tcp)
            .await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake::<_, Reply>(TokioIo::new(tls)).await?;
        drop(tokio::spawn(connection));
        let path = url.path_and_query().map_or("/", |path| path.as_str());
        let authority = url.authority().map_or(host, |authority| authority.as_str());
        let request = Request::get(path)
            .header(hyper::header::HOST, authority)
            .header(hyper::header::ACCEPT, "application/json")
            .body(Reply::empty())
            .map_err(|_| FetchError::Url)?;
        let response = sender.send_request(request).await?;
        // Redirects are not followed: any status but 200 fails the fetch.
        if response.status() != StatusCode::OK {
            return Err(FetchError::Status(response.status()));
        }
        let freshness = Freshness::of(response.headers(), SystemTime::now());
        let body = body_within(response.into_body(), MAX_BODY)
            .await
            .ok_or(FetchError::Body)?;
        Ok((body, freshness))
    }
}

/// The whole body of `body`, at most `max` bytes.
async fn body_within(mut body: Incoming, max: usize) -> Option<Vec<u8>> {
    if body.size_hint().lower() > max as u64 {
        return None;
    }
    let mut out = Vec::new();
    loop {
        match std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
            None => return Some(out),
            Some(Err(_)) => return None,
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    if out.len().checked_add(data.len())? > max {
                        return None;
                    }
                    out.extend_from_slice(&data);
                }
            }
        }
    }
}

/// The fetch in flight, until it ends: dropped before
/// [`InFlight::disarm`] (the request that started it was cancelled), it
/// ends it as a failure ([`Jwks::abandon`]).
struct InFlight<'a>(Option<&'a Jwks>);

impl InFlight<'_> {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if let Some(jwks) = self.0.take() {
            jwks.abandon();
        }
    }
}

/// A response's freshness lifetime and current age (RFC 9111 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Freshness {
    /// How long it is fresh, from its generation.
    pub lifetime: Duration,
    /// How old it already is when received (RFC 9111 §4.2.3): the larger
    /// of its `Age` and its apparent age, the time since its `Date`.
    pub age: Duration,
    /// Its `Age` alone: how long caches held it. Zero for a response from
    /// the origin.
    pub held: Duration,
    /// Its `Expires` governs its lifetime (no `max-age`, no `no-cache`)
    /// and is at or before its `Date` (or this clock, without one), or is
    /// not a date (RFC 9111 §5.3): explicitly expired, never usable, not
    /// even by the request that fetched it.
    pub expired: bool,
}

impl Freshness {
    /// Its age has reached a positive lifetime, or a cache held a response
    /// of zero lifetime: no request may use it. A zero lifetime from the
    /// origin serves the request that fetched it, whatever its `Date`
    /// (whose one-second resolution would otherwise decide).
    fn stale_on_receipt(&self) -> bool {
        if self.expired {
            true
        } else if self.lifetime.is_zero() {
            !self.held.is_zero()
        } else {
            self.age >= self.lifetime
        }
    }
}

impl Freshness {
    /// The freshness of a response with `headers`, received at `now`:
    /// `max-age`, else `Expires` minus `Date` (or minus `now` without
    /// `Date`), else zero; zero for `no-store` or `no-cache`; never more
    /// than the issuer says.
    #[must_use]
    pub fn of(headers: &hyper::HeaderMap, now: SystemTime) -> Self {
        let text = |name: hyper::header::HeaderName| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
        };
        let held = text(hyper::header::AGE)
            .and_then(|age| age.parse::<u64>().ok())
            .map_or(Duration::ZERO, Duration::from_secs);
        let date = text(hyper::header::DATE).and_then(http_date);
        let now_seconds = unix_seconds(now);
        // A `Date` ahead of this clock gives no apparent age, never a
        // negative one.
        let apparent = match (date, now_seconds) {
            (Some(date), Some(now)) => Duration::from_secs(now.saturating_sub(date)),
            _ => Duration::ZERO,
        };
        let age = held.max(apparent);
        let mut max_age = None;
        let mut uncacheable = false;
        for directive in headers
            .get_all(hyper::header::CACHE_CONTROL)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
        {
            let directive = directive.trim();
            let (name, value) = directive.split_once('=').unwrap_or((directive, ""));
            match name.trim().to_ascii_lowercase().as_str() {
                "no-store" | "no-cache" => uncacheable = true,
                "max-age" => {
                    // An invalid max-age makes the response stale (§4.2.1).
                    max_age = Some(value.trim().trim_matches('"').parse::<u64>().unwrap_or(0));
                }
                _ => {}
            }
        }
        let mut expired = false;
        let lifetime = if uncacheable {
            Duration::ZERO
        } else if let Some(seconds) = max_age {
            Duration::from_secs(seconds)
        } else {
            let date = date.or(now_seconds);
            match (text(hyper::header::EXPIRES).map(http_date), date) {
                (Some(Some(expires)), Some(date)) if expires > date => {
                    Duration::from_secs(expires - date)
                }
                // At or before its date, or not a date: already expired.
                (Some(_), _) => {
                    expired = true;
                    Duration::ZERO
                }
                (None, _) => Duration::ZERO,
            }
        };
        Self {
            lifetime,
            age,
            held,
            expired,
        }
    }
}

fn unix_seconds(time: SystemTime) -> Option<u64> {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

/// Seconds since the epoch of IMF-fixdate `text` (RFC 9110 §5.6.7,
/// `Sun, 06 Nov 1994 08:49:37 GMT`); `None` for any other form, which
/// makes the response's lifetime zero.
#[must_use]
pub fn http_date(text: &str) -> Option<u64> {
    let mut words = text.split(' ');
    let (Some(_), Some(day), Some(month), Some(year), Some(time), Some("GMT"), None) = (
        words.next(),
        words.next(),
        words.next(),
        words.next(),
        words.next(),
        words.next(),
        words.next(),
    ) else {
        return None;
    };
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month = u64::try_from(MONTHS.iter().position(|name| *name == month)?).ok()? + 1;
    // IMF-fixdate's day is two digits and its year four: a longer year
    // could overflow the day count below.
    let digits =
        |text: &str, len: usize| text.len() == len && text.bytes().all(|b| b.is_ascii_digit());
    if !digits(day, 2) || !digits(year, 4) {
        return None;
    }
    let (day, year): (u64, u64) = (day.parse().ok()?, year.parse().ok()?);
    let mut clock = time.split(':').map(|part| part.parse::<u64>().ok());
    let (Some(Some(hour)), Some(Some(minute)), Some(Some(second)), None) =
        (clock.next(), clock.next(), clock.next(), clock.next())
    else {
        return None;
    };
    if !(1..=31).contains(&day) || year < 1970 || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    // Days from the civil date (H. Hinnant's algorithm), from 1970-01-01.
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146_097 + doe).checked_sub(719_468)?;
    days.checked_mul(86_400)?
        .checked_add(hour * 3600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    fn freshness(headers: &[(&'static str, &str)]) -> Freshness {
        let mut map = hyper::HeaderMap::new();
        for (name, value) in headers {
            let _ = map.append(*name, value.parse().unwrap());
        }
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(784_111_777);
        Freshness::of(&map, now)
    }

    /// The lifetime is the issuer's, never raised; `no-store`, `no-cache`
    /// and missing metadata give zero; `Age` is kept.
    #[test]
    fn freshness_is_the_issuers() {
        let lifetime = |headers| freshness(headers).lifetime.as_secs();
        assert_eq!(lifetime(&[("cache-control", "max-age=0")]), 0);
        assert_eq!(lifetime(&[("cache-control", "public, max-age=30")]), 30);
        assert_eq!(
            lifetime(&[("cache-control", "max-age=600, must-revalidate")]),
            600
        );
        assert_eq!(lifetime(&[("cache-control", "max-age=600, no-cache")]), 0);
        assert_eq!(
            lifetime(&[
                ("cache-control", "no-store"),
                ("cache-control", "max-age=9")
            ]),
            0
        );
        assert_eq!(lifetime(&[("cache-control", "max-age=abc")]), 0);
        assert_eq!(lifetime(&[]), 0);
        assert_eq!(
            lifetime(&[
                ("date", "Sun, 06 Nov 1994 08:49:37 GMT"),
                ("expires", "Sun, 06 Nov 1994 08:59:37 GMT")
            ]),
            600
        );
        assert_eq!(
            lifetime(&[("expires", "Sun, 06 Nov 1994 08:59:37 GMT")]),
            600
        );
        assert_eq!(lifetime(&[("expires", "0")]), 0);
        assert_eq!(
            freshness(&[("cache-control", "max-age=60"), ("age", "45")]).age,
            Duration::from_secs(45)
        );
    }

    /// The age counts from `Date` when no `Age` says more (RFC 9111
    /// §4.2.3): an old `Date`, or an `Expires` already past, is stale on
    /// receipt; a `Date` ahead of this clock adds nothing.
    #[test]
    fn the_age_counts_from_date() {
        // `now` is 08:49:37.
        let old = freshness(&[
            ("cache-control", "max-age=300"),
            ("date", "Sun, 06 Nov 1994 08:39:37 GMT"),
        ]);
        assert_eq!(old.age, Duration::from_secs(600));
        assert_eq!(old.held, Duration::ZERO);
        assert!(old.stale_on_receipt());
        let expired = freshness(&[
            ("date", "Sun, 06 Nov 1994 08:29:37 GMT"),
            ("expires", "Sun, 06 Nov 1994 08:39:37 GMT"),
        ]);
        assert_eq!(expired.lifetime, Duration::from_secs(600));
        assert!(expired.stale_on_receipt());
        let recent = freshness(&[
            ("cache-control", "max-age=300"),
            ("date", "Sun, 06 Nov 1994 08:48:37 GMT"),
            ("age", "30"),
        ]);
        assert_eq!(recent.age, Duration::from_secs(60));
        assert!(!recent.stale_on_receipt());
        let ahead = freshness(&[
            ("cache-control", "max-age=300"),
            ("date", "Sun, 06 Nov 1994 09:49:37 GMT"),
        ]);
        assert_eq!(ahead.age, Duration::ZERO);
        // An `Expires` at or before its `Date` (or this clock, without
        // one), or not a date, is explicitly expired: never the zero
        // lifetime exception.
        for headers in [
            &[("expires", "Sun, 06 Nov 1994 08:39:37 GMT")][..],
            &[
                ("date", "Sun, 06 Nov 1994 08:49:37 GMT"),
                ("expires", "Sun, 06 Nov 1994 08:49:37 GMT"),
            ],
            &[("expires", "0")],
        ] {
            let explicit = freshness(headers);
            assert!(
                explicit.expired && explicit.stale_on_receipt(),
                "{headers:?}"
            );
        }
        // `max-age` governs over a past `Expires` (§5.3).
        assert!(
            !freshness(&[
                ("cache-control", "max-age=60"),
                ("expires", "Sun, 06 Nov 1994 08:39:37 GMT")
            ])
            .stale_on_receipt()
        );
        assert!(!freshness(&[]).stale_on_receipt());
        // A zero lifetime from the origin serves its request whatever its
        // `Date`; one a cache held does not.
        let origin = freshness(&[
            ("cache-control", "no-cache"),
            ("date", "Sun, 06 Nov 1994 08:49:30 GMT"),
        ]);
        assert!(!origin.stale_on_receipt());
        assert!(freshness(&[("cache-control", "no-cache"), ("age", "1")]).stale_on_receipt());
    }

    #[test]
    fn http_dates_parse() {
        assert_eq!(
            http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            http_date("Tue, 29 Feb 2028 12:00:00 GMT"),
            Some(1_835_438_400)
        );
        for bad in [
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "",
            "x",
            "Sun, 06 Nov 99999999999999999 08:49:37 GMT",
            "Sun, 06 Nov 18446744073709551615 08:49:37 GMT",
            "Sun, 06 Nov 994 08:49:37 GMT",
            "Sun, 6 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov +994 08:49:37 GMT",
        ] {
            assert_eq!(http_date(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_budget_backs_off_to_its_cap() {
        let budget = Budget::default();
        assert_eq!(budget.wait(0), Duration::from_secs(30));
        assert_eq!(budget.wait(1), Duration::from_secs(60));
        assert_eq!(budget.wait(4), Duration::from_secs(300));
        assert_eq!(budget.wait(u32::MAX), Duration::from_secs(300));
        // A budget past what a deadline holds is held to a day, so no
        // deadline overflows.
        let huge = Budget::new(Duration::MAX, Duration::MAX);
        assert_eq!(huge.wait(0), Budget::MAX);
        assert_eq!(huge.wait(u32::MAX), Budget::MAX);
        let now = Instant::now();
        assert_eq!(huge.next(now, u32::MAX), now + Budget::MAX);
    }

    /// The request that starts a fetch is cancelled while the issuer has
    /// not answered: the fetch ends as a failure, and the next request
    /// starts another instead of waiting on one that never ends.
    #[test]
    fn a_cancelled_fetch_ends_and_the_next_request_starts_one() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            // It accepts connections and never answers.
            let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let issuer = format!("https://{}", silent.local_addr().unwrap());
            let jwks = Jwks::new(
                Issuer::new(&issuer, Vec::new())
                    .with_budget(Budget::new(Duration::ZERO, Duration::ZERO)),
            )
            .unwrap();
            for generation in 1..=2 {
                let cancelled =
                    tokio::time::timeout(Duration::from_millis(50), jwks.keys_for("k")).await;
                assert!(cancelled.is_err());
                let state = jwks.lock();
                assert!(!state.in_flight);
                assert_eq!(state.generation, generation);
                assert_eq!(state.failures, u32::try_from(generation).unwrap());
                assert!(state.fetched.is_none());
            }
        });
    }
}
