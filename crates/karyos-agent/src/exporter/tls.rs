// SPDX-License-Identifier: Apache-2.0

//! The exporter's TLS (karyos#887; the exporter TLS admission record,
//! widening the agent HTTP stack record): `rustls` with the
//! `rustls-graviola` provider, TLS 1.3 only although `tls12` is compiled
//! in, server authentication with a certificate and key from PEM files,
//! no client certificates (a scrape carries the bearer token). The
//! provider's CPU requirements are checked first, so a CPU without them
//! is a typed refusal at start, never a panic at the first handshake.

use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Why the exporter's TLS configuration could not be made.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// The CPU lacks a feature the TLS provider requires.
    #[error("the CPU lacks `{0}`, which the TLS provider requires")]
    Cpu(&'static str),
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
}

/// The features `graviola` requires on x86_64.
#[cfg(target_arch = "x86_64")]
fn features() -> [(&'static str, bool); 7] {
    [
        ("aes", std::is_x86_feature_detected!("aes")),
        ("ssse3", std::is_x86_feature_detected!("ssse3")),
        ("avx", std::is_x86_feature_detected!("avx")),
        ("avx2", std::is_x86_feature_detected!("avx2")),
        ("adx", std::is_x86_feature_detected!("adx")),
        ("bmi2", std::is_x86_feature_detected!("bmi2")),
        ("pclmulqdq", std::is_x86_feature_detected!("pclmulqdq")),
    ]
}

/// The features `graviola` requires on aarch64.
#[cfg(target_arch = "aarch64")]
fn features() -> [(&'static str, bool); 4] {
    [
        ("aes", std::arch::is_aarch64_feature_detected!("aes")),
        ("sha2", std::arch::is_aarch64_feature_detected!("sha2")),
        ("pmull", std::arch::is_aarch64_feature_detected!("pmull")),
        ("neon", std::arch::is_aarch64_feature_detected!("neon")),
    ]
}

/// Whether this CPU has every feature the TLS provider requires.
///
/// # Errors
///
/// [`TlsError::Cpu`] with the first feature missing.
pub fn check_cpu() -> Result<(), TlsError> {
    match features().into_iter().find(|(_, present)| !present) {
        Some((name, _)) => Err(TlsError::Cpu(name)),
        None => Ok(()),
    }
}

/// The exporter's TLS configuration from the certificate chain in PEM
/// file `cert` and the private key in PEM file `key`: TLS 1.3 only, no
/// client certificates, `http/1.1` offered by ALPN.
///
/// # Errors
///
/// [`TlsError::Cpu`] for a CPU without the provider's features,
/// [`TlsError::Pem`] for a file that cannot be read or holds no
/// certificate or key, and [`TlsError::Rustls`] for a chain or key
/// `rustls` refuses.
pub fn server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, TlsError> {
    check_cpu()?;
    let pem = |path: &Path, reason: String| TlsError::Pem {
        path: path.display().to_string(),
        reason,
    };
    let chain = CertificateDer::pem_file_iter(cert)
        .map_err(|error| pem(cert, error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| pem(cert, error.to_string()))?;
    if chain.is_empty() {
        return Err(pem(cert, "no certificate".to_owned()));
    }
    let key = PrivateKeyDer::from_pem_file(key).map_err(|error| pem(key, error.to_string()))?;
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
