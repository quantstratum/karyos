// SPDX-License-Identifier: Apache-2.0

//! The `karyos-agent` binary's command line (M7).

use std::path::PathBuf;
use std::time::Duration;

/// What `karyos-agent` prints for a bad command line.
pub const USAGE: &str = "\
usage: karyos-agent --api-dir DIR --driver DIR [--driver DIR]... \
--role UID=ROLE [--role UID=ROLE]... [--refresh-ms MS] [--lag-bytes N] \
[--lag-refreshes N] [--loss-quiet N]

Serves API v1 (JSON) on DIR/agent.sock to the uids given a role (viewer,
operator, risk-officer, administrator), reading each driver's CnC as a
tool every MS milliseconds (default 1000). A uid takes one role. Alerts:
a subscriber lagging N bytes or more (default 8 MiB) for N consecutive
refreshes (default 3); losses, cleared after N quiet refreshes (default
10). Linux only.

A request is one line: KARYOS-AGENT 1 view
";

/// The default refresh period.
pub const DEFAULT_REFRESH: Duration = Duration::from_secs(1);

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Args {
    /// The API socket's directory.
    pub api_dir: PathBuf,
    /// The drivers' admission socket directories.
    pub drivers: Vec<PathBuf>,
    /// Each uid allowed to connect, with its role's name.
    pub roles: Vec<(u32, String)>,
    /// How often the agent reads the drivers.
    pub refresh: Duration,
    /// The alert rules.
    pub alerts: crate::alerts::AlertRules,
}

/// Parses `args` (without the program name); `None` for anything this
/// usage does not describe.
#[must_use]
pub fn parse(args: &[String]) -> Option<Args> {
    let mut api_dir = None;
    let mut drivers = Vec::new();
    let mut roles = Vec::new();
    let mut refresh = DEFAULT_REFRESH;
    let mut alerts = crate::alerts::AlertRules::default();
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let value = args.next()?;
        match flag.as_str() {
            "--api-dir" if api_dir.is_none() => api_dir = Some(PathBuf::from(value)),
            "--driver" => drivers.push(PathBuf::from(value)),
            "--role" => {
                let (uid, role) = value.split_once('=')?;
                if !matches!(
                    role,
                    "viewer" | "operator" | "risk-officer" | "administrator"
                ) {
                    return None;
                }
                let uid: u32 = uid.parse().ok()?;
                // One role per uid: a second is a mistake to refuse.
                if roles.iter().any(|(taken, _)| *taken == uid) {
                    return None;
                }
                roles.push((uid, role.to_owned()));
            }
            "--refresh-ms" => {
                let millis: u64 = value.parse().ok()?;
                if millis == 0 {
                    return None;
                }
                refresh = Duration::from_millis(millis);
            }
            "--lag-bytes" => alerts = alerts.with_lag_bytes(value.parse().ok()?),
            "--lag-refreshes" => {
                alerts = alerts.with_lag_refreshes(value.parse().ok().filter(|n| *n > 0)?);
            }
            "--loss-quiet" => {
                alerts = alerts.with_loss_quiet(value.parse().ok().filter(|n| *n > 0)?);
            }
            _ => return None,
        }
    }
    if drivers.is_empty() || roles.is_empty() {
        return None;
    }
    Some(Args {
        api_dir: api_dir?,
        drivers,
        roles,
        refresh,
        alerts,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn a_full_command_line_parses() {
        let parsed = parse(&args(
            "--api-dir /run/agent --driver /run/a --driver /run/b \
             --role 1000=viewer --role 0=administrator --refresh-ms 250 \
             --lag-bytes 4096 --lag-refreshes 5 --loss-quiet 7",
        ))
        .unwrap();
        assert_eq!(parsed.api_dir, PathBuf::from("/run/agent"));
        assert_eq!(parsed.drivers.len(), 2);
        assert_eq!(
            parsed.roles,
            [(1000, "viewer".to_owned()), (0, "administrator".to_owned())]
        );
        assert_eq!(parsed.refresh, Duration::from_millis(250));
        assert_eq!(
            parsed.alerts,
            crate::alerts::AlertRules::default()
                .with_lag_bytes(4096)
                .with_lag_refreshes(5)
                .with_loss_quiet(7)
        );
    }

    #[test]
    fn anything_else_is_refused() {
        for line in [
            "",
            "--api-dir /a --role 1=viewer",
            "--api-dir /a --driver /d",
            "--driver /d --role 1=viewer",
            "--api-dir /a --driver /d --role 1=root",
            "--api-dir /a --driver /d --role x=viewer",
            "--api-dir /a --driver /d --role 1viewer",
            "--api-dir /a --driver /d --role 1=viewer --refresh-ms 0",
            "--api-dir /a --api-dir /b --driver /d --role 1=viewer",
            "--api-dir /a --driver /d --role 1=viewer --bogus x",
            "--api-dir /a --driver /d --role 1=viewer --driver",
            "--api-dir /a --driver /d --role 1=viewer --role 1=operator",
            "--api-dir /a --driver /d --role 1=viewer --lag-refreshes 0",
            "--api-dir /a --driver /d --role 1=viewer --loss-quiet 0",
            "--api-dir /a --driver /d --role 1=viewer --lag-bytes -1",
        ] {
            assert_eq!(parse(&args(line)), None, "{line}");
        }
    }
}
