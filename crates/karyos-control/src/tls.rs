// SPDX-License-Identifier: Apache-2.0

//! TLS 1.3 with mutual TLS (owner item 43; the agent HTTP stack's
//! admission record, condition 5): `rustls` with the `rustls-graviola`
//! provider, TLS 1.3 only although `tls12` is compiled in, and every
//! client's certificate verified by `rustls`'s own `rustls-webpki`
//! verifier against the configured client CA. A client without a
//! certificate is refused at the handshake unless an issuer's tokens are
//! taken ([`ClientAuth::Optional`]).

use std::path::Path;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConfig, WebPkiClientVerifier};

/// Why the TLS configuration could not be made.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// The CPU cannot run the TLS provider.
    #[error(transparent)]
    Cpu(#[from] crate::cpu::CpuError),
    /// A PEM file could not be read or holds nothing of its kind.
    #[error("{path}: {reason}")]
    Pem {
        /// The file.
        path: String,
        /// What was wrong.
        reason: String,
    },
    /// `rustls` refused the configuration.
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    /// The client verifier could not be built.
    #[error(transparent)]
    Verifier(#[from] rustls::server::VerifierBuilderError),
}

/// The certificates of PEM file `path`, at least one.
///
/// # Errors
///
/// [`TlsError::Pem`] for a file that cannot be read or holds none.
pub fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let pem = |reason: String| TlsError::Pem {
        path: path.display().to_string(),
        reason,
    };
    let certificates = CertificateDer::pem_file_iter(path)
        .map_err(|error| pem(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| pem(error.to_string()))?;
    if certificates.is_empty() {
        return Err(pem("no certificate".to_owned()));
    }
    Ok(certificates)
}

/// The private key of PEM file `path`.
///
/// # Errors
///
/// [`TlsError::Pem`] for a file that cannot be read or holds no key.
pub fn private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    PrivateKeyDer::from_pem_file(path).map_err(|error| TlsError::Pem {
        path: path.display().to_string(),
        reason: error.to_string(),
    })
}

/// Whether a client must present a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientAuth {
    /// Every client (services only).
    Required,
    /// A client may present none (people with bearer tokens, when an
    /// issuer is configured); one it presents must still chain to a root.
    Optional,
}

/// The server's TLS configuration: TLS 1.3 only, the certificate `chain`
/// with `key`, and client certificates chained to one of `client_roots`,
/// required or not as `client_auth` says. Checks the provider's CPU
/// requirements first.
///
/// # Errors
///
/// [`TlsError`] for a CPU without the provider's features, a root, a
/// chain or a key `rustls` refuses.
pub fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_roots: Vec<CertificateDer<'static>>,
    client_auth: ClientAuth,
) -> Result<Arc<ServerConfig>, TlsError> {
    crate::cpu::check()?;
    let provider = Arc::new(rustls_graviola::default_provider());
    let mut roots = RootCertStore::empty();
    for root in client_roots {
        roots.add(root)?;
    }
    let builder =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider));
    let verifier = match client_auth {
        ClientAuth::Required => builder.build()?,
        ClientAuth::Optional => builder.allow_unauthenticated().build()?,
    };
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
