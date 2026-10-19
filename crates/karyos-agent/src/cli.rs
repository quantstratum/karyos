// SPDX-License-Identifier: Apache-2.0

//! The `karyos-agent` binary's command line (M7).

use std::path::PathBuf;
use std::time::Duration;

/// What `karyos-agent` prints for a bad command line.
pub const USAGE: &str = "\
usage: karyos-agent --api-dir DIR --driver DIR [--driver DIR]... \
--role UID=ROLE [--role UID=ROLE]... [--refresh-ms MS]

Serves API v1 (JSON) on DIR/agent.sock to the uids given a role (viewer,
operator, risk-officer, administrator), reading each driver's CnC as a
tool every MS milliseconds (default 1000). Linux only.

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
}

/// Parses `args` (without the program name); `None` for anything this
/// usage does not describe.
#[must_use]
pub fn parse(args: &[String]) -> Option<Args> {
    let mut api_dir = None;
    let mut drivers = Vec::new();
    let mut roles = Vec::new();
    let mut refresh = DEFAULT_REFRESH;
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
                roles.push((uid.parse().ok()?, role.to_owned()));
            }
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
    if drivers.is_empty() || roles.is_empty() {
        return None;
    }
    Some(Args {
        api_dir: api_dir?,
        drivers,
        roles,
        refresh,
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
             --role 1000=viewer --role 0=administrator --refresh-ms 250",
        ))
        .unwrap();
        assert_eq!(parsed.api_dir, PathBuf::from("/run/agent"));
        assert_eq!(parsed.drivers.len(), 2);
        assert_eq!(
            parsed.roles,
            [(1000, "viewer".to_owned()), (0, "administrator".to_owned())]
        );
        assert_eq!(parsed.refresh, Duration::from_millis(250));
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
or ::1): the exporter has no TLS and no authentication. Linux only.
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
