// SPDX-License-Identifier: Apache-2.0

//! The agent's alert rules (SPEC §11, alerting; quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md, M9), evaluated at every
//! refresh of a driver from what the refresh read, so every platform tests
//! them.
//!
//! - **Lag.** A subscriber whose lag is at or above
//!   [`AlertRules::lag_bytes`] in [`AlertRules::lag_refreshes`]
//!   consecutive consistent samples fires; one consistent sample below the
//!   bound, or the subscriber gone, clears it, and so does a refresh that
//!   reads nothing (the driver closed or cannot be attached). A sample
//!   whose values may mix passes changes nothing, either way.
//! - **Loss.** A refresh whose loss report grew (records read or
//!   overwritten unread: both are unrecoverable losses) fires the driver's
//!   loss alert, which counts the records; [`AlertRules::loss_quiet`]
//!   refreshes without a new one clear it, a refresh that reads nothing
//!   included. A new driver instance starts the count over.
//!
//! An alert carries the host time of the refresh at which it began firing.

use std::collections::BTreeMap;

use crate::api::{Alert, AlertKind, Sample};

/// The default lag bound: 8 MiB.
pub const DEFAULT_LAG_BYTES: u64 = 8 << 20;
/// The default number of consecutive samples a lag must hold.
pub const DEFAULT_LAG_REFRESHES: u32 = 3;
/// The default number of quiet refreshes that clear a loss alert.
pub const DEFAULT_LOSS_QUIET: u32 = 10;

/// The declared rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AlertRules {
    /// The lag, in bytes, at or above which a subscriber lags.
    pub lag_bytes: u64,
    /// Consecutive consistent samples a lag must hold to fire, at least 1.
    pub lag_refreshes: u32,
    /// Refreshes without a new loss that clear a loss alert, at least 1.
    pub loss_quiet: u32,
}

impl Default for AlertRules {
    fn default() -> Self {
        Self {
            lag_bytes: DEFAULT_LAG_BYTES,
            lag_refreshes: DEFAULT_LAG_REFRESHES,
            loss_quiet: DEFAULT_LOSS_QUIET,
        }
    }
}

impl AlertRules {
    /// With subscribers lagging at `lag_bytes` or more.
    #[must_use]
    pub fn with_lag_bytes(mut self, lag_bytes: u64) -> Self {
        self.lag_bytes = lag_bytes;
        self
    }

    /// With a lag firing after `lag_refreshes` consecutive samples.
    #[must_use]
    pub fn with_lag_refreshes(mut self, lag_refreshes: u32) -> Self {
        self.lag_refreshes = lag_refreshes;
        self
    }

    /// With a loss alert clearing after `loss_quiet` quiet refreshes.
    #[must_use]
    pub fn with_loss_quiet(mut self, loss_quiet: u32) -> Self {
        self.loss_quiet = loss_quiet;
        self
    }
}

/// One subscriber's lag state: consecutive samples at or above the bound,
/// the time the run began, and its last lag.
#[derive(Debug, Clone, Copy)]
struct Lagging {
    samples: u32,
    /// The time it began firing, once its samples reached the rule's.
    since: Option<u64>,
    lag: u64,
}

/// The driver's loss alert while it fires.
#[derive(Debug, Clone, Copy)]
struct Losing {
    count: u64,
    since: u64,
    quiet: u32,
}

/// One driver's alert state across refreshes.
#[derive(Debug, Default)]
pub(crate) struct Alerts {
    lagging: BTreeMap<(u64, u8, u64), Lagging>,
    /// The loss report's records reported (read and overwritten) at the
    /// last refresh, for this instance.
    losses_seen: u64,
    losing: Option<Losing>,
}

impl Alerts {
    /// A refresh that read nothing: the driver closed or cannot be
    /// attached (IMPLEMENT's F1 on #477). Its subscribers are gone, so
    /// every lag alert clears; no loss was reported, so it is a quiet
    /// refresh for the loss alert.
    pub(crate) fn detached(&mut self, rules: &AlertRules) {
        self.lagging.clear();
        self.losing = self.losing.and_then(|losing| {
            let quiet = losing.quiet.checked_add(1).unwrap_or(losing.quiet);
            (quiet < rules.loss_quiet.max(1)).then_some(Losing { quiet, ..losing })
        });
    }

    /// A new driver instance: its rings start over, so the loss baseline
    /// does; a loss alert firing stays until it clears.
    pub(crate) fn restart(&mut self) {
        self.losses_seen = 0;
    }

    /// Evaluates the rules after a refresh at host time `now` that read
    /// `sample` (if any) and saw the loss report's records reach
    /// `losses_reported` (read plus overwritten, this instance).
    pub(crate) fn update(
        &mut self,
        rules: &AlertRules,
        sample: Option<&Sample>,
        losses_reported: u64,
        now: u64,
    ) {
        if let Some(sample) = sample.filter(|sample| sample.consistent) {
            let mut seen = BTreeMap::new();
            for lane in &sample.lanes {
                for subscriber in &lane.subscribers {
                    let key = (lane.stream, lane.lane, subscriber.registration);
                    let lag = subscriber
                        .lag
                        .and_then(|lag| u64::try_from(lag).ok())
                        .filter(|lag| *lag >= rules.lag_bytes);
                    if let Some(lag) = lag {
                        // Checked: at its end the count keeps its value.
                        let samples = self.lagging.get(&key).map_or(1, |state| {
                            state.samples.checked_add(1).unwrap_or(state.samples)
                        });
                        let since = self
                            .lagging
                            .get(&key)
                            .and_then(|state| state.since)
                            .or((samples >= rules.lag_refreshes.max(1)).then_some(now));
                        let state = Lagging {
                            samples,
                            since,
                            lag,
                        };
                        let _ = seen.insert(key, state);
                    }
                }
            }
            // A subscriber below the bound, or gone, clears.
            self.lagging = seen;
        }
        let new = losses_reported
            .checked_sub(self.losses_seen)
            .unwrap_or(losses_reported);
        self.losses_seen = losses_reported;
        self.losing = match (self.losing, new) {
            (None, 0) => None,
            (None, new) => Some(Losing {
                count: new,
                since: now,
                quiet: 0,
            }),
            (Some(losing), 0) => {
                let quiet = losing.quiet.checked_add(1).unwrap_or(losing.quiet);
                (quiet < rules.loss_quiet.max(1)).then_some(Losing { quiet, ..losing })
            }
            (Some(losing), new) => Some(Losing {
                count: losing.count.checked_add(new).unwrap_or(losing.count),
                quiet: 0,
                ..losing
            }),
        };
    }

    /// The alerts firing.
    pub(crate) fn firing(&self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = self
            .lagging
            .iter()
            .filter_map(|(&(stream, lane, participant), state)| {
                Some(Alert {
                    kind: AlertKind::Lag,
                    stream,
                    lane,
                    participant,
                    value: state.lag,
                    since: state.since?,
                })
            })
            .collect();
        if let Some(losing) = self.losing {
            alerts.push(Alert {
                kind: AlertKind::Loss,
                stream: 0,
                lane: 0,
                participant: 0,
                value: losing.count,
                since: losing.since,
            });
        }
        alerts
    }
}

#[cfg(test)]
mod tests;
