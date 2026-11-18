// SPDX-License-Identifier: Apache-2.0

//! The `karyos-control` binary's command line.

use std::net::SocketAddr;
use std::path::PathBuf;

/// What `karyos-control` prints for a bad command line.
pub const USAGE: &str = "\
usage: karyos-control --listen ADDR:PORT --cert PEM --key PEM --client-ca PEM \
--agent-socket PATH --service NAME=PEM [--service NAME=PEM]... \
[--max-connections N]

Serves the agent's API v1 over HTTPS (TLS 1.3 only) on ADDR:PORT with the
certificate chain of --cert and its key, to clients presenting a
certificate of --client-ca (mutual TLS). A client whose certificate is the
one of a --service's PEM is that service, relayed to the agent on
--agent-socket as principal NAME; any other is refused with 403. Run it as
the uid the agent's --relay names; the agent gives each principal its role.
Routes: GET /v1/view, GET /v1/capabilities, POST /v1/request with one v1
request as the body (guard-close DIR GUARD REASON, ...).
";

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Args {
    /// Where to listen.
    pub listen: SocketAddr,
    /// The server's certificate chain, PEM.
    pub cert: PathBuf,
    /// Its private key, PEM.
    pub key: PathBuf,
    /// The client CA's certificates, PEM.
    pub client_ca: PathBuf,
    /// The agent's API socket.
    pub agent_socket: PathBuf,
    /// Each service's principal name and certificate file.
    pub services: Vec<(String, PathBuf)>,
    /// The connections served at once.
    pub max_connections: usize,
}

/// Parses `args` (without the program name); `None` for anything this
/// usage does not describe.
#[must_use]
pub fn parse(args: &[String]) -> Option<Args> {
    let (mut listen, mut cert, mut key, mut client_ca, mut agent_socket) =
        (None, None, None, None, None);
    let mut services: Vec<(String, PathBuf)> = Vec::new();
    let mut max_connections = crate::server::DEFAULT_MAX_CONNECTIONS;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let value = args.next()?;
        match flag.as_str() {
            "--listen" if listen.is_none() => listen = Some(value.parse().ok()?),
            "--cert" if cert.is_none() => cert = Some(PathBuf::from(value)),
            "--key" if key.is_none() => key = Some(PathBuf::from(value)),
            "--client-ca" if client_ca.is_none() => client_ca = Some(PathBuf::from(value)),
            "--agent-socket" if agent_socket.is_none() => {
                agent_socket = Some(PathBuf::from(value));
            }
            "--service" => {
                let (name, path) = value.split_once('=')?;
                if !crate::relay::valid_principal(name)
                    || path.is_empty()
                    || services.iter().any(|(taken, _)| taken == name)
                {
                    return None;
                }
                services.push((name.to_owned(), PathBuf::from(path)));
            }
            "--max-connections" => {
                max_connections = value.parse().ok().filter(|n| *n > 0)?;
            }
            _ => return None,
        }
    }
    if services.is_empty() {
        return None;
    }
    Some(Args {
        listen: listen?,
        cert: cert?,
        key: key?,
        client_ca: client_ca?,
        agent_socket: agent_socket?,
        services,
        max_connections,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    fn parse(line: &str) -> Option<super::Args> {
        super::parse(&line.split(' ').map(str::to_owned).collect::<Vec<_>>())
    }

    #[test]
    fn a_command_line_parses() {
        let base = "--listen 127.0.0.1:8443 --cert c --key k --client-ca ca --agent-socket s";
        let args = parse(&format!(
            "{base} --service svc.ops=o.pem --max-connections 8"
        ))
        .unwrap();
        assert_eq!(args.services, [("svc.ops".to_owned(), "o.pem".into())]);
        assert_eq!(args.max_connections, 8);
        for bad in [
            "",
            "--service svc/ops=o.pem",
            "--service svc.ops=",
            "--service a=x --service a=y",
            "--service a=x --max-connections 0",
            "--service a=x --listen 127.0.0.1:1",
            "--service a=x --role administrator",
        ] {
            assert_eq!(parse(&format!("{base} {bad}")), None, "{bad}");
        }
        assert_eq!(parse("--cert c --key k --service a=x"), None);
    }
}
