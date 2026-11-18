// SPDX-License-Identifier: Apache-2.0

//! The `karyos-agent` binary's command line (M7).

use std::path::PathBuf;
use std::time::Duration;

/// What `karyos-agent` prints for a bad command line.
pub const USAGE: &str = "\
usage: karyos-agent --api-dir DIR --driver DIR [--driver DIR]... \
--role UID=ROLE [--role UID=ROLE]... [--refresh-ms MS] [--lag-bytes N] \
[--lag-refreshes N] [--loss-quiet N] [--archive DIR=REQ,RESP]... \
[--journal DIR] [--agent-id NAME] [--relay UID=ID]... \
[--principal NAME=OPERATOR:ROLE]... [--relay-group GID]

Serves API v1 (JSON) on DIR/agent.sock to the uids given a role (viewer,
operator, risk-officer, administrator, registrar), reading each driver's
CnC as a tool every MS milliseconds (default 1000). A uid takes one role. Alerts:
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
example namespace/pod; the agent looks no name up. --relay lets the uid
of a remote control-plane component (karyos-control) carry requests for
the principals of --principal, each recorded as its OPERATOR id (not a
--role uid) with its ROLE; the relay's ID (1 or more) is journalled beside
the operator. A relayed request is KARYOS-AGENT 1 relay NAME REQUEST; its
role is the principal's here, never the relay's. --relay-group lets the
members of GID, which this agent's uid must belong to, reach DIR/agent.sock
(DIR 0710, the socket 0660, both of GID): a relay under a uid of its own
joins it; without it DIR is 0700 and the socket 0600. Linux only.

A request is one line: KARYOS-AGENT 1 view, or
KARYOS-AGENT 1 guard-close DIR GUARD [REASON] (operator, risk-officer),
KARYOS-AGENT 1 guard-reopen DIR GUARD EPOCH [REASON] (risk-officer,
administrator), KARYOS-AGENT 1 gap-ack POSITION (administrator),
KARYOS-AGENT 1 limits [DIMENSION=VALUE ...], KARYOS-AGENT 1 capabilities
(each capability served, unavailable here or forbidden for the role), or
the join metadata registry's KARYOS-AGENT 1 join-put DIR KIND KEY
NAME=VALUE... and join-retire DIR KIND KEY (registrar, administrator),
join-get DIR KIND KEY [AT_NS] and join-list DIR [KIND KEY], KIND being
stream, point or counter.
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
    /// Each relay's uid and relay id (karyos#708).
    pub relays: Vec<(u32, u64)>,
    /// Each principal a relay may carry: its name, operator id and role
    /// name.
    pub principals: Vec<(String, u32, String)>,
    /// The group whose members may reach the socket (karyos#708).
    pub relay_group: Option<u32>,
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
    let mut relays: Vec<(u32, u64)> = Vec::new();
    let mut principals: Vec<(String, u32, String)> = Vec::new();
    let mut relay_group = None;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let value = args.next()?;
        match flag.as_str() {
            "--api-dir" if api_dir.is_none() => api_dir = Some(PathBuf::from(value)),
            "--journal" if journal.is_none() => journal = Some(PathBuf::from(value)),
            "--agent-id" if agent_id.is_none() => {
                if !crate::api::valid_agent_id(value) {
                    return None;
                }
                agent_id = Some(value.clone());
            }
            "--relay-group" if relay_group.is_none() => {
                relay_group = Some(value.parse::<u32>().ok()?);
            }
            "--driver" => drivers.push(PathBuf::from(value)),
            "--role" => {
                let (uid, role) = value.split_once('=')?;
                if !matches!(
                    role,
                    "viewer" | "operator" | "risk-officer" | "administrator" | "registrar"
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
            "--relay" => {
                let (uid, id) = value.split_once('=')?;
                let (uid, id): (u32, u64) = (uid.parse().ok()?, id.parse().ok()?);
                // A relay id of 0 is the local socket's in the journal.
                if id == 0
                    || relays
                        .iter()
                        .any(|(taken, other)| *taken == uid || *other == id)
                {
                    return None;
                }
                relays.push((uid, id));
            }
            "--principal" => {
                let (name, rest) = value.split_once('=')?;
                let (operator, role) = rest.split_once(':')?;
                let operator: u32 = operator.parse().ok()?;
                if !crate::api::valid_principal(name)
                    || !matches!(
                        role,
                        "viewer" | "operator" | "risk-officer" | "administrator" | "registrar"
                    )
                    || principals
                        .iter()
                        .any(|(taken, id, _)| taken == name || *id == operator)
                {
                    return None;
                }
                principals.push((name.to_owned(), operator, role.to_owned()));
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
    // A principal's operator id is not a local uid's, so the journal and
    // the audit never mistake one for the other; principals need a relay.
    if drivers.is_empty()
        || roles.is_empty()
        || archives.iter().any(|(dir, _)| !drivers.contains(dir))
        || principals
            .iter()
            .any(|(_, operator, _)| roles.iter().any(|(uid, _)| uid == operator))
        || (relays.is_empty() != principals.is_empty())
        || (relay_group.is_some() && relays.is_empty())
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
        relays,
        principals,
        relay_group,
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
[--refresh-ms MS] [--agent-id NAME] [--token-file PATH]

Serves the agent's view of each driver in the Prometheus text format on
http://ADDRESS:PORT/metrics, reading each driver's CnC as a tool every MS
milliseconds (default 1000). ADDRESS must be a loopback address (127.0.0.1
or ::1): the exporter has no TLS, so expose it beyond the pod through a
TLS-terminating sidecar or mesh. --token-file requires every scrape to
carry Authorization: Bearer with the token in PATH (32 to 256 bytes of
visible ASCII, the file mode 0600; a symlink is followed, as a Kubernetes
secret mount is one), against the other processes of the pod's network
namespace; only /metrics needs it. --agent-id names the exporter in its
karyos_exporter_info (1 to 64 bytes of A-Z a-z 0-9 . _ : / -). It takes
one of each driver's tool slots (max_tools) while attached. No OTLP.
Linux only.
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
    /// The name it reports as its identity (`--agent-id`).
    pub agent_id: Option<String>,
    /// The file holding the bearer token every scrape must carry
    /// (`--token-file`).
    pub token_file: Option<PathBuf>,
}

/// Parses `karyos-exporter`'s `args` (without the program name); `None`
/// for anything its usage does not describe, a non-loopback address
/// included.
#[must_use]
pub fn parse_exporter(args: &[String]) -> Option<ExporterArgs> {
    let mut listen = None;
    let mut drivers = Vec::new();
    let mut refresh = DEFAULT_REFRESH;
    let mut agent_id = None;
    let mut token_file = None;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let value = args.next()?;
        match flag.as_str() {
            "--agent-id" if agent_id.is_none() => {
                if !crate::api::valid_agent_id(value) {
                    return None;
                }
                agent_id = Some(value.clone());
            }
            "--token-file" if token_file.is_none() => token_file = Some(PathBuf::from(value)),
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
        agent_id,
        token_file,
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
        // An identity and a token file (karyos#734).
        let parsed = parse_exporter(&args(
            "--listen 127.0.0.1:9464 --driver /d --agent-id ns/pod-0 --token-file /run/t",
        ))
        .unwrap();
        assert_eq!(parsed.agent_id.as_deref(), Some("ns/pod-0"));
        assert_eq!(parsed.token_file, Some(PathBuf::from("/run/t")));
        assert_eq!(
            parse_exporter(&args("--listen 127.0.0.1:1 --driver /d"))
                .unwrap()
                .token_file,
            None
        );
        for refused in [
            "--listen 0.0.0.0:9464 --driver /d",
            "--listen 192.168.1.2:9464 --driver /d",
            "--listen [::]:9464 --driver /d",
            "--listen localhost:9464 --driver /d",
            "--listen 127.0.0.1:9464",
            "--driver /d",
            "--listen 127.0.0.1:1 --listen 127.0.0.1:2 --driver /d",
            "--listen 127.0.0.1:1 --driver /d --refresh-ms 0",
            "--listen 127.0.0.1:1 --driver /d --agent-id has space",
            "--listen 127.0.0.1:1 --driver /d --token-file /a --token-file /b",
            "--listen 127.0.0.1:1 --driver /d --role 1=viewer",
        ] {
            assert_eq!(parse_exporter(&args(refused)), None, "{refused}");
        }
    }

    /// Relays and principals (karyos#708): a principal's operator id may
    /// not be a local uid's, a relay id is not 0, and one needs the other.
    #[test]
    fn relays_and_principals_parse() {
        let parse =
            |line: &str| super::parse(&line.split(' ').map(str::to_owned).collect::<Vec<_>>());
        let base = "--api-dir /a --driver /d --role 1000=viewer";
        let parsed = parse(&format!(
            "{base} --relay 990=7 --principal svc.ops=50001:operator"
        ))
        .unwrap();
        assert_eq!(parsed.relays, [(990, 7)]);
        assert_eq!(parsed.relay_group, None);
        let grouped = parse(&format!(
            "{base} --relay 990=7 --principal svc.ops=50001:operator --relay-group 990"
        ))
        .unwrap();
        assert_eq!(grouped.relay_group, Some(990));
        assert_eq!(
            parsed.principals,
            [("svc.ops".to_owned(), 50001, "operator".to_owned())]
        );
        for bad in [
            "--relay 990=0 --principal a=1:viewer",
            "--relay 990=7 --principal a=1000:viewer",
            "--relay 990=7 --principal a=1:root",
            "--relay 990=7 --principal a/b=1:viewer",
            "--relay 990=7 --principal a=1:viewer --principal a=2:viewer",
            "--relay 990=7 --principal a=1:viewer --principal b=1:viewer",
            "--relay 990=7 --relay 990=8 --principal a=1:viewer",
            "--relay 990=7",
            "--principal a=1:viewer",
            "--relay-group 990",
            "--relay 990=7 --principal a=1:viewer --relay-group x",
            "--relay 990=7 --principal a=1:viewer --relay-group 1 --relay-group 2",
        ] {
            assert_eq!(parse(&format!("{base} {bad}")), None, "{bad}");
        }
    }
}
