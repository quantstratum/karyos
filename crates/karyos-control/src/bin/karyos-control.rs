// SPDX-License-Identifier: Apache-2.0

//! `karyos-control`: the agent's API v1 over HTTPS with mutual TLS
//! (karyos#708). See `karyos_control::cli::USAGE`.

use std::io::Write;
use std::process::ExitCode;

use karyos_control::{cli, jwks, jwt, server, tls};

fn main() -> ExitCode {
    // A non-UTF-8 argument is a usage error, never a panic.
    let args: Option<Vec<String>> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string().ok())
        .collect();
    let Some(args) = args.as_deref().and_then(cli::parse) else {
        let _ = write!(std::io::stderr(), "{}", cli::USAGE);
        return ExitCode::from(2);
    };
    match start(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "karyos-control: {error}");
            ExitCode::from(1)
        }
    }
}

/// Why the component did not start or stopped.
#[derive(Debug, thiserror::Error)]
enum StartError {
    #[error(transparent)]
    Tls(#[from] tls::TlsError),
    #[error(transparent)]
    Serve(#[from] server::ControlError),
    #[error("{0}: one certificate expected, the service's own")]
    Service(String),
    #[error("--oidc-ca: {0}")]
    Anchors(#[from] rustls::Error),
}

fn start(args: cli::Args) -> Result<(), StartError> {
    let client_auth = match args.oidc {
        Some(_) => tls::ClientAuth::Optional,
        None => tls::ClientAuth::Required,
    };
    let config = tls::server_config(
        tls::certificates(&args.cert)?,
        tls::private_key(&args.key)?,
        tls::certificates(&args.client_ca)?,
        client_auth,
    )?;
    let mut services = Vec::new();
    for (name, path) in &args.services {
        let mut certificates = tls::certificates(path)?.into_iter();
        let (Some(certificate), None) = (certificates.next(), certificates.next()) else {
            return Err(StartError::Service(path.display().to_string()));
        };
        services.extend(server::Service::new(name, certificate));
    }
    let mut config = server::ControlConfig::new(config, services, args.agent_socket)
        .with_max_connections(args.max_connections);
    if let Some(oidc) = args.oidc {
        let mut issuer = jwks::Issuer::new(&oidc.issuer, tls::certificates(&oidc.ca)?);
        if let Some(host) = &oidc.jwks_host {
            issuer = issuer.with_jwks_host(host);
        }
        let policy = jwt::Policy::new(&oidc.issuer, &oidc.audience, &oidc.scope)
            .with_algorithms(oidc.algorithms)
            .with_principal_claim(&oidc.principal_claim);
        config = config.with_oidc(server::Oidc::new(policy, jwks::Jwks::new(issuer)?));
    }
    Ok(server::run(args.listen, config)?)
}
