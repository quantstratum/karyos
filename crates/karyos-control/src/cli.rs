// SPDX-License-Identifier: Apache-2.0

//! The `karyos-control` binary's command line.

use std::net::SocketAddr;
use std::path::PathBuf;

/// What `karyos-control` prints for a bad command line.
pub const USAGE: &str = "\
usage: karyos-control --listen ADDR:PORT --cert PEM --key PEM --client-ca PEM \
--agent-socket PATH [--service NAME=PEM]... [--max-connections N] \
[--oidc-issuer URL --oidc-audience AUD --oidc-scope SCOPE --oidc-ca PEM \
[--oidc-algorithms ALG,...] [--oidc-principal-claim CLAIM] \
[--oidc-jwks-host HOST]]

Serves the agent's API v1 over HTTPS (TLS 1.3 only) on ADDR:PORT with the
certificate chain of --cert and its key, to clients presenting a
certificate of --client-ca (mutual TLS). A client whose certificate is the
one of a --service's PEM is that service, relayed to the agent on
--agent-socket as principal NAME; any other is refused with 403. Run it as
the uid the agent's --relay names; the agent gives each principal its role.
With --oidc-issuer, people present the issuer's agent-audience access
tokens (Authorization: Bearer), which they get by signing in to the issuer
with the authorization code flow and PKCE in the console; a client may then
connect without a certificate. A token is verified against the issuer's
keys, fetched from its discovery document over TLS 1.3 trusting --oidc-ca
only: issuer, audience AUD, type at+jwt, expiry, signature (ALG among
--oidc-algorithms, default ES256; ES256, RS256, PS256, EdDSA), scope SCOPE,
and its principal claim (default sub), relayed as the principal. Once the
issuer's key set is past the lifetime the issuer gave it, or cannot be
fetched, every token is refused with 503 until a fetch succeeds.
At least one --service or --oidc-issuer is required.
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
    /// People's tokens, if taken.
    pub oidc: Option<OidcArgs>,
}

/// The issuer whose tokens are taken.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OidcArgs {
    /// Its identifier, an `https` URL.
    pub issuer: String,
    /// The agent audience.
    pub audience: String,
    /// The API scope token.
    pub scope: String,
    /// The anchors of its TLS certificates, PEM.
    pub ca: PathBuf,
    /// The algorithms taken.
    pub algorithms: Vec<crate::jwt::Algorithm>,
    /// The principal claim.
    pub principal_claim: String,
    /// Another host its key set may be on.
    pub jwks_host: Option<String>,
}

/// Parses `args` (without the program name); `None` for anything this
/// usage does not describe.
#[must_use]
pub fn parse(args: &[String]) -> Option<Args> {
    let (mut listen, mut cert, mut key, mut client_ca, mut agent_socket) =
        (None, None, None, None, None);
    let mut services: Vec<(String, PathBuf)> = Vec::new();
    let mut max_connections = crate::server::DEFAULT_MAX_CONNECTIONS;
    let (mut issuer, mut audience, mut scope, mut ca) = (None, None, None, None);
    let (mut algorithms, mut principal_claim, mut jwks_host) = (None, None, None);
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
            "--oidc-issuer" if issuer.is_none() => {
                if !value.starts_with("https://") {
                    return None;
                }
                issuer = Some(value.clone());
            }
            "--oidc-audience" if audience.is_none() && !value.is_empty() => {
                audience = Some(value.clone());
            }
            "--oidc-scope" if scope.is_none() && !value.is_empty() && !value.contains(' ') => {
                scope = Some(value.clone());
            }
            "--oidc-ca" if ca.is_none() => ca = Some(PathBuf::from(value)),
            "--oidc-algorithms" if algorithms.is_none() => {
                let parsed: Option<Vec<_>> =
                    value.split(',').map(crate::jwt::Algorithm::parse).collect();
                algorithms = Some(parsed?);
            }
            "--oidc-principal-claim" if principal_claim.is_none() && !value.is_empty() => {
                principal_claim = Some(value.clone());
            }
            "--oidc-jwks-host" if jwks_host.is_none() && !value.is_empty() => {
                jwks_host = Some(value.clone());
            }
            "--max-connections" => {
                max_connections = value.parse().ok().filter(|n| *n > 0)?;
            }
            _ => return None,
        }
    }
    let oidc = match (issuer, audience, scope, ca) {
        (Some(issuer), Some(audience), Some(scope), Some(ca)) => Some(OidcArgs {
            issuer,
            audience,
            scope,
            ca,
            algorithms: algorithms.unwrap_or_else(|| vec![crate::jwt::Algorithm::Es256]),
            principal_claim: principal_claim.unwrap_or_else(|| "sub".to_owned()),
            jwks_host,
        }),
        (None, None, None, None)
            if algorithms.is_none() && principal_claim.is_none() && jwks_host.is_none() =>
        {
            None
        }
        _ => return None,
    };
    if services.is_empty() && oidc.is_none() {
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
        oidc,
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
        let oidc = "--oidc-issuer https://id.example --oidc-audience karyos-agent \
                    --oidc-scope karyos.api --oidc-ca id.pem";
        let args = parse(&format!("{base} {oidc} --oidc-algorithms ES256,EdDSA")).unwrap();
        let taken = args.oidc.unwrap();
        assert!(args.services.is_empty());
        assert_eq!(taken.algorithms.len(), 2);
        assert_eq!(taken.principal_claim, "sub");
        for bad in [
            "--oidc-issuer http://id.example --oidc-audience a --oidc-scope s --oidc-ca c",
            "--oidc-issuer https://id.example --oidc-audience a --oidc-scope s",
            "--oidc-issuer https://id.example --oidc-audience a --oidc-scope s --oidc-ca c \
             --oidc-algorithms ES256,HS256",
            "--oidc-issuer https://id.example --oidc-audience a --oidc-scope 'a b' --oidc-ca c",
            "--oidc-algorithms ES256 --service a=x",
        ] {
            assert_eq!(parse(&format!("{base} {bad}")), None, "{bad}");
        }
    }
}
