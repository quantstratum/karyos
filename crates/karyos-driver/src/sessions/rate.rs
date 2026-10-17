// SPDX-License-Identifier: Apache-2.0

//! Message rates per source or destination endpoint
//! (`quantstratum-docs: karyos/design/network-control-schemas.md` §7.4):
//! one message bucket ([`karyos_sys::rate_limit::RateLimiter`]) per
//! endpoint in a bounded table. An entry idle for a second is full again
//! (its burst is its rate per second) and may be reused for another
//! endpoint, which grants nothing early; with no reusable entry, a new
//! endpoint is refused. IPv4-mapped IPv6 endpoints count as their IPv4
//! endpoint, so one host cannot double its budget.

use std::net::SocketAddr;

use karyos_sys::host_clock::age_ns;
use karyos_sys::rate_limit::{Rate, RateLimiter, RatePolicy};

/// A second in ns.
const SECOND: u64 = 1_000_000_000;

/// Why [`EndpointRates::admit`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateRefused {
    /// The endpoint's bucket is empty.
    Limited,
    /// The table is full of endpoints active within the last second.
    TableFull,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    endpoint: SocketAddr,
    limiter: RateLimiter,
    last: u64,
}

/// One message bucket per endpoint, in a bounded table.
#[derive(Debug)]
pub struct EndpointRates {
    entries: Vec<Entry>,
    max: usize,
    policy: RatePolicy,
}

impl EndpointRates {
    /// `per_second` messages per endpoint, also the burst, for at most
    /// `max` endpoints (allocated here). `None` for a zero rate or table.
    #[must_use]
    pub fn new(per_second: u64, max: usize) -> Option<Self> {
        if per_second == 0 || max == 0 {
            return None;
        }
        Some(Self {
            entries: Vec::with_capacity(max),
            max,
            policy: RatePolicy {
                messages: Rate {
                    per_second,
                    burst: per_second,
                },
                bytes: None,
            },
        })
    }

    /// Whether one message to `endpoint` would be admitted at `now`,
    /// charging nothing: its bucket is refilled to `now` and checked, and an
    /// endpoint with no entry needs room in the table (a free or idle one).
    ///
    /// # Errors
    ///
    /// [`RateRefused`], as [`EndpointRates::admit`] would answer.
    pub fn would_admit(&mut self, endpoint: SocketAddr, now: u64) -> Result<(), RateRefused> {
        let endpoint = normalized(endpoint);
        let room = self.entries.len() < self.max
            || self
                .entries
                .iter()
                .any(|entry| age_ns(now, entry.last) >= SECOND);
        match self
            .entries
            .iter_mut()
            .find(|entry| entry.endpoint == endpoint)
        {
            Some(entry) => {
                entry.limiter.refill_at(now);
                if entry.limiter.admits(0, true) {
                    Ok(())
                } else {
                    Err(RateRefused::Limited)
                }
            }
            None if room => Ok(()),
            None => Err(RateRefused::TableFull),
        }
    }

    /// Charges one message to `endpoint` at `now`.
    ///
    /// # Errors
    ///
    /// [`RateRefused`]: nothing is charged.
    pub fn admit(&mut self, endpoint: SocketAddr, now: u64) -> Result<(), RateRefused> {
        let endpoint = normalized(endpoint);
        let index = match self
            .entries
            .iter()
            .position(|entry| entry.endpoint == endpoint)
        {
            Some(index) => index,
            None => {
                let fresh = Entry {
                    endpoint,
                    limiter: RateLimiter::new(self.policy, now),
                    last: now,
                };
                if self.entries.len() < self.max {
                    self.entries.push(fresh);
                    self.entries
                        .len()
                        .checked_sub(1)
                        .ok_or(RateRefused::TableFull)?
                } else {
                    let idle = self
                        .entries
                        .iter()
                        .position(|entry| age_ns(now, entry.last) >= SECOND)
                        .ok_or(RateRefused::TableFull)?;
                    if let Some(slot) = self.entries.get_mut(idle) {
                        *slot = fresh;
                    }
                    idle
                }
            }
        };
        let entry = self.entries.get_mut(index).ok_or(RateRefused::TableFull)?;
        entry.last = now;
        if entry.limiter.admit_frame(now, 0, true) {
            Ok(())
        } else {
            Err(RateRefused::Limited)
        }
    }
}

/// One message bucket for every message together (a per-driver total).
#[derive(Debug, Clone, Copy)]
pub struct TotalRate {
    limiter: RateLimiter,
}

impl TotalRate {
    /// `per_second` messages, also the burst, starting full at `now`.
    /// `None` for a zero rate.
    #[must_use]
    pub fn new(per_second: u64, now: u64) -> Option<Self> {
        (per_second > 0).then(|| Self {
            limiter: RateLimiter::new(
                RatePolicy {
                    messages: Rate {
                        per_second,
                        burst: per_second,
                    },
                    bytes: None,
                },
                now,
            ),
        })
    }

    /// Charges one message at `now`; `false` when the bucket is empty.
    pub fn admit(&mut self, now: u64) -> bool {
        self.limiter.admit_frame(now, 0, true)
    }

    /// Whether one message would be admitted at `now`, charging nothing
    /// (the bucket is refilled to `now`).
    pub fn would_admit(&mut self, now: u64) -> bool {
        self.limiter.refill_at(now);
        self.limiter.admits(0, true)
    }
}

/// An endpoint as rates and §7.3 see it: an IPv4-mapped IPv6 endpoint is
/// its IPv4 endpoint.
#[must_use]
pub fn normalized(endpoint: SocketAddr) -> SocketAddr {
    match endpoint {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map_or(endpoint, |v4| SocketAddr::from((v4, v6.port()))),
        SocketAddr::V4(_) => endpoint,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers, as ADR-0007 allows in tests"
    )]

    use super::*;

    /// `would_admit` charges nothing and answers as `admit` would.
    #[test]
    fn would_admit_charges_nothing() {
        let a: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:1".parse().unwrap();
        let mut rates = EndpointRates::new(1, 1).unwrap();
        for _ in 0..3 {
            assert_eq!(rates.would_admit(a, 0), Ok(()));
        }
        rates.admit(a, 0).unwrap();
        assert_eq!(rates.would_admit(a, 1), Err(RateRefused::Limited));
        assert_eq!(rates.admit(a, 1), Err(RateRefused::Limited));
        // The table holds one endpoint, busy within the second.
        assert_eq!(rates.would_admit(b, 1), Err(RateRefused::TableFull));
        assert_eq!(rates.admit(b, 1), Err(RateRefused::TableFull));
        // A second after the last charge attempt (a refused one counts as
        // use) the bucket refilled and the entry is idle.
        assert_eq!(rates.would_admit(a, SECOND + 1), Ok(()));
        assert_eq!(rates.would_admit(b, SECOND + 1), Ok(()));
        let mut total = TotalRate::new(1, 0).unwrap();
        assert!(total.would_admit(0));
        assert!(total.would_admit(0));
        assert!(total.admit(0));
        assert!(!total.would_admit(1));
        assert!(total.would_admit(SECOND));
    }
}
