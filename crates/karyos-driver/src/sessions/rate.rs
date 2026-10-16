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
