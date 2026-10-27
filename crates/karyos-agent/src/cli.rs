// SPDX-License-Identifier: Apache-2.0

//! The `karyos-agent` binary's command line (M7).

use std::path::PathBuf;
use std::time::Duration;

/// What `karyos-agent` prints for a bad command line.
pub const USAGE: &str = "\
usage: karyos-agent --api-dir DIR --driver DIR [--driver DIR]... \
--role UID=ROLE [--role UID=ROLE]... [--refresh-ms MS] [--lag-bytes N] \
[--lag-refreshes N] [--loss-quiet N] [--archive DIR=REQ,RESP]... \
[--journal DIR] [--agent-id NAME]

Serves API v1 (JSON) on DIR/agent.sock to the uids given a role (viewer,
operator, risk-officer, administrator), reading each driver's CnC as a
tool every MS milliseconds (default 1000). A uid takes one role. Alerts:
a subscriber lagging N bytes or more (default 8 MiB) for N consecutive
refreshes (default 3); losses, cleared after N quiet refreshes (default
10); a guard close that senders have not applied past the driver's
guard_ack_timeout; an unknown interval in the operations journal, until
an administrator acknowledges it. --archive lists the Archive catalog of
the driver in DIR (one of the --driver directories) over the control
streams REQ, which the host configures concurrent, and RESP; off by
default, it costs one client slot of that driver. Guard operations are
journalled in the --journal directory, an Archive directory; without
one, reopens are refused. --agent-id names this agent in its view (1 to
64 bytes of A-Z a-z 0-9 . _ : / -), as its deployment calls it, for
example namespace/pod; the agent looks no name up. Linux only.

A request is one line: KARYOS-AGENT 1 view, or
KARYOS-AGENT 1 guard-close DIR GUARD [REASON] (operator, risk-officer),
KARYOS-AGENT 1 guard-reopen DIR GUARD EPOCH [REASON] (risk-officer,
administrator), KARYOS-AGENT 1 gap-ack POSITION (administrator).
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
    /// The operations journal's directory (M10b).
    pub journal: Option<PathBuf>,
    /// The drivers whose Archive catalog is listed, and its streams.
    pub archives: Vec<(PathBuf, crate::catalog::ArchiveStreams)>,
    /// The agent's own name (R-CORE-24).
    pub agent_id: Option<String>,
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
    let mut journal = None;
    let mut archives: Vec<(PathBuf, crate::catalog::ArchiveStreams)> = Vec::new();
    let mut agent_id = None;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let value = args.next()?;
        match flag.as_str() {
            "--api-dir" if api_dir.is_none() => api_dir = Some(PathBuf::from(value)),
            "--journal" if journal.is_none() => journal = Some(PathBuf::from(value)),
            "--agent-id" if agent_id.is_none() => {
                let valid = (1..=64).contains(&value.len())
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte));
                if !valid {
                    return None;
                }
                agent_id = Some(value.clone());
            }
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
            "--archive" => {
                let (dir, streams) = value.split_once('=')?;
                let (requests, responses) = streams.split_once(',')?;
                let (requests, responses) = (requests.parse().ok()?, responses.parse().ok()?);
                let dir = PathBuf::from(dir);
                // One Archive per driver, on two distinct streams.
                if requests == responses || archives.iter().any(|(taken, _)| *taken == dir) {
                    return None;
                }
                archives.push((
                    dir,
                    crate::catalog::ArchiveStreams::new(requests, responses),
                ));
            }
            _ => return None,
        }
    }
    // An Archive names one of the drivers.
    if drivers.is_empty()
        || roles.is_empty()
        || archives.iter().any(|(dir, _)| !drivers.contains(dir))
    {
        return None;
    }
    Some(Args {
        api_dir: api_dir?,
        drivers,
        roles,
        refresh,
        alerts,
        journal,
        archives,
        agent_id,
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
             --lag-bytes 4096 --lag-refreshes 5 --loss-quiet 7 \
             --archive /run/b=100,101 --journal /var/lib/karyos/journal \
             --agent-id prod/agent-0",
        ))
        .unwrap();
        assert_eq!(parsed.agent_id.as_deref(), Some("prod/agent-0"));
        assert_eq!(
            parsed.archives,
            [(
                PathBuf::from("/run/b"),
                crate::catalog::ArchiveStreams::new(100, 101)
            )]
        );
        assert_eq!(parsed.api_dir, PathBuf::from("/run/agent"));
        assert_eq!(
            parsed.journal,
            Some(PathBuf::from("/var/lib/karyos/journal"))
        );
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
            // An Archive of a driver not watched, on one stream, twice, or
            // misspelled.
            "--api-dir /a --driver /d --role 1=viewer --archive /e=1,2",
            "--api-dir /a --driver /d --role 1=viewer --archive /d=1,1",
            "--api-dir /a --driver /d --role 1=viewer --archive /d=1,2 --archive /d=3,4",
            "--api-dir /a --driver /d --role 1=viewer --archive /d=1",
            "--api-dir /a --driver /d --role 1=viewer --archive /d=x,2",
            "--api-dir /a --driver /d --role 1=viewer --archive /d",
            "--api-dir /a --driver /d --role 1=viewer --agent-id",
            "--api-dir /a --driver /d --role 1=viewer --agent-id ns/pod --agent-id x",
            "--api-dir /a --driver /d --role 1=viewer --agent-id a+b",
            "--api-dir /a --driver /d --role 1=viewer --agent-id é",
        ] {
            assert_eq!(parse(&args(line)), None, "{line}");
        }
    }
}

/// What `karyos-exporter` prints for a bad command line.
pub const EXPORTER_USAGE: &str = "\
usage: karyos-exporter --listen ADDRESS:PORT --driver DIR [--driver DIR]... \
[--refresh-ms MS]

Serves the agent's view of each driver in the Prometheus text format on
http://ADDRESS:PORT/metrics, reading each driver's CnC as a tool every MS
milliseconds (default 1000). ADDRESS must be a loopback address (127.0.0.1
or ::1): the exporter has no TLS and no authentication. It takes one of
each driver's tool slots (max_tools) while attached. Linux only.
";

/// A parsed `karyos-exporter` command line.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExporterArgs {
    /// The loopback address to listen on.
    pub listen: std::net::SocketAddr,
    /// The drivers' admission socket directories.
    pub drivers: Vec<PathBuf>,
    /// How often the agent reads the drivers.
    pub refresh: Duration,
}

/// Parses `karyos-exporter`'s `args` (without the program name); `None`
/// for anything its usage does not describe, a non-loopback address
/// included.
#[must_use]
pub fn parse_exporter(args: &[String]) -> Option<ExporterArgs> {
    let mut listen = None;
    let mut drivers = Vec::new();
    let mut refresh = DEFAULT_REFRESH;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let value = args.next()?;
        match flag.as_str() {
            "--listen" if listen.is_none() => {
                let address: std::net::SocketAddr = value.parse().ok()?;
                if !address.ip().is_loopback() {
                    return None;
                }
                listen = Some(address);
            }
            "--driver" => drivers.push(PathBuf::from(value)),
            "--refresh-ms" => {
                let millis: u64 = value.parse().ok()?;
                if millis == 0 {
                    return None;
                }
                refresh = Duration::from_millis(millis);
            }
            _ => return None,
        }
    }
    if drivers.is_empty() {
        return None;
    }
    Some(ExporterArgs {
        listen: listen?,
        drivers,
        refresh,
    })
}

#[cfg(test)]
mod exporter_tests {
    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn the_exporter_listens_on_loopback_only() {
        let parsed = parse_exporter(&args(
            "--listen 127.0.0.1:9464 --driver /d --driver /e --refresh-ms 250",
        ))
        .unwrap();
        assert_eq!(parsed.listen, "127.0.0.1:9464".parse().unwrap());
        assert_eq!(parsed.drivers.len(), 2);
        assert_eq!(parsed.refresh, Duration::from_millis(250));
        assert!(parse_exporter(&args("--listen [::1]:9464 --driver /d")).is_some());
        for refused in [
            "--listen 0.0.0.0:9464 --driver /d",
            "--listen 192.168.1.2:9464 --driver /d",
            "--listen [::]:9464 --driver /d",
            "--listen localhost:9464 --driver /d",
            "--listen 127.0.0.1:9464",
            "--driver /d",
            "--listen 127.0.0.1:1 --listen 127.0.0.1:2 --driver /d",
            "--listen 127.0.0.1:1 --driver /d --refresh-ms 0",
            "--listen 127.0.0.1:1 --driver /d --role 1=viewer",
        ] {
            assert_eq!(parse_exporter(&args(refused)), None, "{refused}");
        }
    }
}
