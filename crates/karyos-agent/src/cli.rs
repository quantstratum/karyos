// SPDX-License-Identifier: Apache-2.0

//! The `karyos-agent` binary's command line (M7).

use std::path::PathBuf;
use std::time::Duration;

/// What `karyos-agent` prints for a bad command line.
pub const USAGE: &str = "\
usage: karyos-agent --api-dir DIR --driver DIR [--driver DIR]... \
--role UID=ROLE [--role UID=ROLE]... [--refresh-ms MS] [--lag-bytes N] \
[--lag-refreshes N] [--loss-quiet N] [--archive DIR=REQ,RESP[,STATE]]... \
[--journal DIR] [--agent-id NAME] [--relay UID=ID]... \
[--principal NAME=OPERATOR:ROLE]... [--relay-group GID] [--stop-timeout-ms MS] \
[--two-person CLASS[,CLASS...]]... [--approval-wait MS] \
[--journal-retention POLICY] [--journal-copy LOCATION=DIR]... [--journal-trust FILE] \\
[--journal-anchors HEX=DIR]...

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
joins it; without it DIR is 0700 and the socket 0600. SIGTERM or SIGINT
stops the agent cleanly: it writes its durable `agent stopped` journal
record and exits 0, within MS milliseconds (default 5000); past that
deadline, on a second signal, or when the record cannot be made durable
it exits nonzero and the next start records an unknown interval. A
service manager sends SIGTERM and waits at least MS plus one refresh
before SIGKILL. --two-person marks operation classes for two people
(R-CORE-20): guard-reopen, or cluster-command:CLUSTER/COMMAND (a guard
close cannot be marked); a marked operation is answered pending_approval,
performs nothing, and waits for approve OPID by another principal, or
withdraw OPID by its requester, for --approval-wait MS milliseconds
(default 600000, 10 minutes; at most 86400000, 24 hours); it needs the
journal. --journal-retention retain_for=DURATION[,purge=manual|after_expiry]
[,min_copies=N] is the journal's retention policy (ADR-0113; DURATION in
ns, us, ms or s; min_copies 1 by default); without it no purge of the journal is allowed, and holds
still apply. --journal-copy names a copy of the journal directory in DIR
held at LOCATION, verified before each purge decision; a purge needs
min_copies of them verified. --journal-trust FILE verifies the journal,
and its copies, under the trust file karyos-catalog verify --trust reads.
--journal-anchors HEX=DIR adds the operator export anchor store in DIR
at location HEX to the journal's verification, as karyos-catalog verify
--anchors: an anchored, trusted, intact range is verified. Each needs
--journal. Linux only.

A request is one line: KARYOS-AGENT 1 view, or
KARYOS-AGENT 1 guard-close DIR GUARD [REASON] (operator, risk-officer),
KARYOS-AGENT 1 guard-reopen DIR GUARD EPOCH [REASON] (risk-officer,
administrator), KARYOS-AGENT 1 gap-ack POSITION (administrator),
KARYOS-AGENT 1 limits [DIMENSION=VALUE ...], KARYOS-AGENT 1 capabilities
(each capability served, unavailable here or forbidden for the role), or
the join metadata registry's KARYOS-AGENT 1 join-put DIR KIND KEY
NAME=VALUE... and join-retire DIR KIND KEY (registrar, administrator),
join-get DIR KIND KEY [AT_NS] and join-list DIR [KIND KEY], KIND being
stream, point or counter, or KARYOS-AGENT 1 rate-change DIR STREAM_ID
SESSION_ID EXPECTED AUTHORITY MSG_RATE MSG_BURST BYTE_RATE BYTE_BURST
[REASON], AUTHORITY safety (operator, risk-officer, administrator) or
administrator (administrator), byte rate and burst 0 0 for no byte limit,
or KARYOS-AGENT 1 guard-close-preview DIR GUARD [REASON] and
guard-reopen-preview DIR GUARD [REASON], then submit OPID TOKEN
guard-close|guard-reopen DIR GUARD [REASON] with the preview's token and
the caller's operation id (the roles of the operation), or KARYOS-AGENT 1
approve OPID and withdraw OPID for an operation pending approval, or
the retention requests legal-hold RECORDING [REASON] (operator,
risk-officer, administrator), hold-release RECORDING [REASON] and purge
RECORDING BEFORE [REASON] (administrator) and seal-verify RECORDING, where
RECORDING is an Archive recording's number or journal, the agent's own
operations journal.
";

/// The default bound of a signal stop (karyos#710).
pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// How long a signal stop may take before the agent exits anyway,
    /// leaving an unclean stop (karyos#710); zero exits at once.
    pub stop_timeout: Duration,
    /// The operation classes marked for two people (karyos#739).
    pub two_person: Vec<crate::two_person::TwoPersonClass>,
    /// How long a marked operation waits for its approval.
    pub approval_wait: Duration,
    /// The journal's retention policy (ADR-0113).
    pub journal_policy: Option<crate::journal::JournalPolicy>,
    /// The journal's copies: each location's name and directory.
    pub journal_copies: Vec<(String, PathBuf)>,
    /// The journal's trust file.
    pub journal_trust: Option<PathBuf>,
    /// The journal's anchor stores: each location and directory.
    pub journal_anchors: Vec<([u8; 32], PathBuf)>,
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
    let mut stop_timeout = None;
    let mut two_person: Vec<crate::two_person::TwoPersonClass> = Vec::new();
    let mut approval_wait = None;
    let mut journal_policy = None;
    let mut journal_copies: Vec<(String, PathBuf)> = Vec::new();
    let mut journal_trust = None;
    let mut journal_anchors: Vec<([u8; 32], PathBuf)> = Vec::new();
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let value = args.next()?;
        match flag.as_str() {
            "--api-dir" if api_dir.is_none() => api_dir = Some(PathBuf::from(value)),
            "--journal" if journal.is_none() => journal = Some(PathBuf::from(value)),
            "--journal-retention" if journal_policy.is_none() => {
                journal_policy = Some(crate::journal::JournalPolicy::parse(value)?);
            }
            "--journal-trust" if journal_trust.is_none() => {
                journal_trust = Some(PathBuf::from(value));
            }
            "--journal-anchors" => {
                let anchors = crate::journal::retention::parse_anchors(value)?;
                if journal_anchors.iter().any(|(taken, _)| *taken == anchors.0) {
                    return None;
                }
                journal_anchors.push(anchors);
            }
            "--journal-copy" => {
                let (location, dir) = value.split_once('=')?;
                // One copy per location, each a directory.
                if location.is_empty()
                    || dir.is_empty()
                    || journal_copies.iter().any(|(taken, _)| taken == location)
                {
                    return None;
                }
                journal_copies.push((location.to_owned(), PathBuf::from(dir)));
            }
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
            // A guard close is no class: it never waits (karyos#739).
            "--two-person" => {
                for class in crate::two_person::TwoPersonClass::parse_list(value)? {
                    if !two_person.contains(&class) {
                        two_person.push(class);
                    }
                }
            }
            "--approval-wait" if approval_wait.is_none() => {
                approval_wait = Some(crate::two_person::parse_wait(value)?);
            }
            "--stop-timeout-ms" if stop_timeout.is_none() => {
                stop_timeout = Some(Duration::from_millis(value.parse().ok()?));
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
                let mut ids = streams.split(',');
                let requests: i32 = ids.next()?.parse().ok()?;
                let responses: i32 = ids.next()?.parse().ok()?;
                // The third, the retention state answer stream (ADR-0101),
                // is optional, as on karyosd's --archive-control.
                let retention = match ids.next() {
                    None => None,
                    Some(id) => Some(id.parse::<i32>().ok()?),
                };
                let dir = PathBuf::from(dir);
                // One Archive per driver, on distinct streams.
                if ids.next().is_some()
                    || requests == responses
                    || retention.is_some_and(|id| id == requests || id == responses)
                    || archives.iter().any(|(taken, _)| *taken == dir)
                {
                    return None;
                }
                let mut streams = crate::catalog::ArchiveStreams::new(requests, responses);
                if let Some(id) = retention {
                    streams = streams.with_retention(id);
                }
                archives.push((dir, streams));
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
        || (journal.is_none()
            && (journal_policy.is_some()
                || !journal_copies.is_empty()
                || journal_trust.is_some()
                || !journal_anchors.is_empty()))
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
        stop_timeout: stop_timeout.unwrap_or(DEFAULT_STOP_TIMEOUT),
        two_person,
        approval_wait: approval_wait.unwrap_or(crate::two_person::DEFAULT_WAIT),
        journal_policy,
        journal_copies,
        journal_trust,
        journal_anchors,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    /// karyos#739: `--two-person` takes the classes, a guard close never;
    /// The journal's retention options (ADR-0113) parse, each needs
    /// `--journal`, and a malformed or repeated one is refused.
    #[test]
    fn the_journal_retention_options_parse() {
        let base = "--api-dir /run/agent --driver /run/a --role 1000=viewer --journal /j";
        let parsed = parse(&args(&format!(
            "{base} --journal-retention retain_for=604800s,purge=after_expiry,min_copies=2 \
             --journal-copy vault=/mnt/vault --journal-copy tape=/mnt/tape \
             --journal-trust /etc/karyos/trust --journal-anchors {}=/mnt/anchors",
            "ab".repeat(32)
        )))
        .unwrap();
        let policy = parsed.journal_policy.unwrap();
        assert_eq!(policy.retain_for_ns, 7 * 86_400_000_000_000);
        assert_eq!(policy.min_copies.get(), 2);
        assert_eq!(
            policy.purge,
            karyos_archive::integrity::retention::PurgeMode::AfterExpiry
        );
        assert_eq!(parsed.journal_copies.len(), 2);
        assert_eq!(
            parsed.journal_trust,
            Some(PathBuf::from("/etc/karyos/trust"))
        );
        assert_eq!(
            parsed.journal_anchors,
            vec![([0xab; 32], PathBuf::from("/mnt/anchors"))]
        );
        let policy = parse(&args(&format!(
            "{base} --journal-retention retain_for=3600s"
        )))
        .unwrap()
        .journal_policy
        .unwrap();
        assert_eq!(policy.min_copies.get(), 1);
        assert_eq!(
            policy.purge,
            karyos_archive::integrity::retention::PurgeMode::Manual
        );
        for bad in [
            "--journal-retention purge=manual",
            "--journal-retention retain_for=0s",
            "--journal-retention retain_for=3600s,min_copies=0",
            "--journal-retention retain_for=3600s,keep=1",
            "--journal-retention retain_for=3600s,retain_for=7200s",
            "--journal-copy vault",
            "--journal-copy vault=/a --journal-copy vault=/b",
            "--journal-trust /a --journal-trust /b",
            "--journal-anchors ab=/a",
            "--journal-anchors /a",
        ] {
            assert!(parse(&args(&format!("{base} {bad}"))).is_none(), "{bad}");
        }
        let without = "--api-dir /run/agent --driver /run/a --role 1000=viewer";
        for option in [
            "--journal-retention retain_for=3600s",
            "--journal-copy vault=/a",
            "--journal-trust /a",
            "--journal-anchors 0000000000000000000000000000000000000000000000000000000000000000=/a",
        ] {
            assert!(
                parse(&args(&format!("{without} {option}"))).is_none(),
                "{option}"
            );
        }
    }

    /// `--approval-wait` defaults to 10 minutes and takes at most 24 hours.
    #[test]
    fn two_person_classes_and_the_wait_parse_within_their_bounds() {
        use crate::two_person::{DEFAULT_WAIT, TwoPersonClass};
        let base = "--api-dir /run/agent --driver /run/a --role 0=administrator";
        let parsed = parse(&args(base)).unwrap();
        assert!(parsed.two_person.is_empty());
        assert_eq!(parsed.approval_wait, DEFAULT_WAIT);
        let parsed = parse(&args(&format!(
            "{base} --two-person guard-reopen,cluster-command:orders/kill \
             --two-person guard-reopen --approval-wait 30000"
        )))
        .unwrap();
        assert_eq!(
            parsed.two_person,
            [
                TwoPersonClass::GuardReopen,
                TwoPersonClass::ClusterCommand {
                    cluster: "orders".to_owned(),
                    command: "kill".to_owned(),
                },
            ]
        );
        assert_eq!(parsed.approval_wait, Duration::from_secs(30));
        for bad in [
            "--two-person guard-close",
            "--two-person guard-reopen,guard-close",
            "--two-person cluster-command:orders",
            "--approval-wait 0",
            "--approval-wait 86400001",
            "--approval-wait 1000 --approval-wait 2000",
        ] {
            assert_eq!(parse(&args(&format!("{base} {bad}"))), None, "{bad}");
        }
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
[--refresh-ms MS] [--agent-id NAME] [--token-file PATH] \
[--tls-cert PEM --tls-key PEM] [--deadline-ms MS]

Serves the agent's view of each driver in the Prometheus text format on
http://ADDRESS:PORT/metrics, reading each driver's CnC as a tool every MS
milliseconds (default 1000). Without TLS, ADDRESS must be a loopback
address (127.0.0.1 or ::1); expose it beyond the pod through a
TLS-terminating sidecar or mesh, or with --tls-cert and --tls-key (both,
PEM files: the certificate chain and its private key), which serve
https://ADDRESS:PORT/metrics over TLS 1.3 on any address, in a build with
the exporter-tls feature; off loopback --token-file is required too, and
the key file must have mode 0600. --deadline-ms bounds each connection
in all, handshake, request and answer included (1 to 30000; default 250
on plain loopback, 2000 over TLS, which fits a remote scrape of about
100 KiB at round trips up to 300 ms). --token-file requires every scrape to
carry Authorization: Bearer with the token in PATH (32 to 256 bytes of
visible ASCII, the file mode 0600; a symlink is followed, as a Kubernetes
secret mount is one), against the other processes of the pod's network
namespace; only /metrics needs it. --agent-id names the exporter in its
karyos_exporter_info (1 to 64 bytes of A-Z a-z 0-9 . _ : / -). It takes
one of each driver's tool slots (max_tools) while attached. OTLP export
of the same metrics is karyos-exporter-otlp, a separate binary.
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
    /// The PEM files of the TLS certificate chain and its private key
    /// (`--tls-cert`, `--tls-key`; karyos#887), both or neither.
    pub tls: Option<(PathBuf, PathBuf)>,
    /// The whole of one connection at most (`--deadline-ms`), when not
    /// the default.
    pub deadline: Option<Duration>,
}

/// Parses `karyos-exporter`'s `args` (without the program name); `None`
/// for anything its usage does not describe: a non-loopback address
/// without TLS, or one of `--tls-cert` and `--tls-key` without the other,
/// included.
#[must_use]
pub fn parse_exporter(args: &[String]) -> Option<ExporterArgs> {
    let mut listen = None;
    let mut drivers = Vec::new();
    let mut refresh = DEFAULT_REFRESH;
    let mut agent_id = None;
    let mut token_file = None;
    let mut tls_cert = None;
    let mut tls_key = None;
    let mut deadline = None;
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
            "--tls-cert" if tls_cert.is_none() => tls_cert = Some(PathBuf::from(value)),
            "--tls-key" if tls_key.is_none() => tls_key = Some(PathBuf::from(value)),
            "--listen" if listen.is_none() => {
                let address: std::net::SocketAddr = value.parse().ok()?;
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
            "--deadline-ms" if deadline.is_none() => {
                let millis: u64 = value.parse().ok()?;
                let chosen = Duration::from_millis(millis);
                if millis == 0 || chosen > crate::exporter::MAX_CONNECTION_DEADLINE {
                    return None;
                }
                deadline = Some(chosen);
            }
            _ => return None,
        }
    }
    if drivers.is_empty() {
        return None;
    }
    let tls = match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => Some((cert, key)),
        (None, None) => None,
        _ => return None,
    };
    let listen: std::net::SocketAddr = listen?;
    // Off loopback only over TLS, and only with a token: the token never
    // crosses the network in clear, and no scrape is open (karyos#887).
    if !listen.ip().is_loopback() && (tls.is_none() || token_file.is_none()) {
        return None;
    }
    Some(ExporterArgs {
        listen,
        drivers,
        refresh,
        agent_id,
        token_file,
        tls,
        deadline,
    })
}

#[cfg(test)]
mod exporter_tests {
    use super::*;

    /// karyos#887 review: `--deadline-ms` takes 1 to 30000 once.
    #[test]
    fn a_deadline_is_bounded() {
        let args = |line: &str| line.split(' ').map(str::to_owned).collect::<Vec<_>>();
        let base = "--listen 127.0.0.1:9464 --driver /d";
        assert_eq!(parse_exporter(&args(base)).unwrap().deadline, None);
        assert_eq!(
            parse_exporter(&args(&format!("{base} --deadline-ms 5000")))
                .unwrap()
                .deadline,
            Some(Duration::from_secs(5))
        );
        for bad in ["0", "30001", "x"] {
            assert_eq!(
                parse_exporter(&args(&format!("{base} --deadline-ms {bad}"))),
                None
            );
        }
        assert_eq!(
            parse_exporter(&args(&format!("{base} --deadline-ms 1 --deadline-ms 2"))),
            None
        );
    }

    /// karyos#887: off loopback only with TLS and a token, and TLS takes
    /// both files.
    #[test]
    fn a_non_loopback_address_needs_both_tls_files() {
        let args = |line: &str| line.split(' ').map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            parse_exporter(&args("--listen 0.0.0.0:9464 --driver /d")),
            None
        );
        assert_eq!(
            parse_exporter(&args(
                "--listen 0.0.0.0:9464 --driver /d --tls-cert /c --tls-key /k"
            )),
            None,
            "off loopback without a token"
        );
        let parsed = parse_exporter(&args(
            "--listen 0.0.0.0:9464 --driver /d --tls-cert /c --tls-key /k --token-file /t",
        ))
        .unwrap();
        assert_eq!(parsed.tls, Some((PathBuf::from("/c"), PathBuf::from("/k"))));
        assert_eq!(
            parse_exporter(&args("--listen 0.0.0.0:9464 --driver /d --tls-cert /c")),
            None
        );
        assert_eq!(
            parse_exporter(&args("--listen 127.0.0.1:9464 --driver /d --tls-key /k")),
            None
        );
        let loopback = parse_exporter(&args(
            "--listen 127.0.0.1:9464 --driver /d --tls-cert /c --tls-key /k",
        ))
        .unwrap();
        assert!(loopback.tls.is_some());
        assert_eq!(
            parse_exporter(&args("--listen 127.0.0.1:9464 --driver /d"))
                .unwrap()
                .tls,
            None
        );
    }

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
