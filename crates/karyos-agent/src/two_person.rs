// SPDX-License-Identifier: Apache-2.0

//! The classes of operations a deployment marks for two people (R-CORE-20,
//! karyos#739; quantstratum-docs: karyos/adr/0112-two-person-pending-approval.md,
//! point 1), and the bounds of the wait for an approval (point 7). The
//! flow itself is [`crate::approval`].

use std::time::Duration;

/// The default wait for an approval (`--approval-wait`).
pub const DEFAULT_WAIT: Duration = Duration::from_secs(10 * 60);

/// The longest wait for an approval `--approval-wait` takes.
pub const MAX_WAIT: Duration = Duration::from_secs(24 * 60 * 60);

/// An operation class `--two-person` marks: only operations that increase
/// risk can be marked, and a guard close, which makes things safer and
/// must never wait, is refused as a class.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TwoPersonClass {
    /// `guard-reopen`.
    GuardReopen,
    /// `cluster-command:<cluster>/<command>`: a product admin command
    /// (R-CORE-41).
    ClusterCommand {
        /// The Cluster's name.
        cluster: String,
        /// The command's name.
        command: String,
    },
}

impl TwoPersonClass {
    /// The class `text` names; `None` for any other text, `guard-close`
    /// included.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        use crate::cluster_admin::valid_name;
        if text == "guard-reopen" {
            return Some(Self::GuardReopen);
        }
        let (cluster, command) = text.strip_prefix("cluster-command:")?.split_once('/')?;
        (valid_name(cluster) && valid_name(command)).then(|| Self::ClusterCommand {
            cluster: cluster.to_owned(),
            command: command.to_owned(),
        })
    }

    /// The classes of `CLASS[,CLASS...]`; `None` when one does not parse.
    #[must_use]
    pub fn parse_list(text: &str) -> Option<Vec<Self>> {
        text.split(',').map(Self::parse).collect()
    }
}

/// The wait `--approval-wait MS` names: 1 ms to [`MAX_WAIT`].
#[must_use]
pub fn parse_wait(millis: &str) -> Option<Duration> {
    let wait = Duration::from_millis(millis.parse().ok()?);
    (!wait.is_zero() && wait <= MAX_WAIT).then_some(wait)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    /// ADR-0112 point 1: a guard close cannot be marked, the two classes
    /// parse, and anything else is refused.
    #[test]
    fn a_guard_close_cannot_be_marked() {
        assert_eq!(TwoPersonClass::parse("guard-close"), None);
        assert_eq!(TwoPersonClass::parse_list("guard-reopen,guard-close"), None);
        assert_eq!(
            TwoPersonClass::parse("guard-reopen"),
            Some(TwoPersonClass::GuardReopen)
        );
        assert_eq!(
            TwoPersonClass::parse_list("guard-reopen,cluster-command:orders/kill").unwrap(),
            [
                TwoPersonClass::GuardReopen,
                TwoPersonClass::ClusterCommand {
                    cluster: "orders".to_owned(),
                    command: "kill".to_owned(),
                },
            ]
        );
        for bad in [
            "",
            "cluster-command:orders",
            "cluster-command:Orders/kill",
            "cluster-command:/kill",
            "rate-change",
        ] {
            assert_eq!(TwoPersonClass::parse(bad), None, "{bad}");
        }
        assert_eq!(parse_wait("600000"), Some(DEFAULT_WAIT));
        assert_eq!(parse_wait("86400000"), Some(MAX_WAIT));
        assert_eq!(parse_wait("86400001"), None);
        assert_eq!(parse_wait("0"), None);
    }
}
