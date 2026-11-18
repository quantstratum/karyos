// SPDX-License-Identifier: Apache-2.0

//! `karyos-control`: the agent's API v1 over HTTPS with mutual TLS
//! (karyos#708). See `karyos_control::cli::USAGE`.

use std::io::Write;
use std::process::ExitCode;

use karyos_control::{cli, server, tls};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(args) = cli::parse(&args) else {
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
}

fn start(args: cli::Args) -> Result<(), StartError> {
    let config = tls::server_config(
        tls::certificates(&args.cert)?,
        tls::private_key(&args.key)?,
        tls::certificates(&args.client_ca)?,
    )?;
    let mut services = Vec::new();
    for (name, path) in &args.services {
        let mut certificates = tls::certificates(path)?.into_iter();
        let (Some(certificate), None) = (certificates.next(), certificates.next()) else {
            return Err(StartError::Service(path.display().to_string()));
        };
        services.extend(server::Service::new(name, certificate));
    }
    let config = server::ControlConfig::new(config, services, args.agent_socket)
        .with_max_connections(args.max_connections);
    Ok(server::run(args.listen, config)?)
}
