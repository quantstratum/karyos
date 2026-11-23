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
    /// The private key file is readable or writable by group or others.
    #[error("{0} must be readable and writable by its owner only (mode 0600)")]
    KeyMode(String),
    /// `rustls` refused the configuration: a key that does not match the
    /// certificate among others.
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
/// file `cert` (leaf first) and the private key in PEM file `key`
/// (PKCS#8, SEC1 or PKCS#1), which only its owner may read or write:
/// TLS 1.3 only, with the provider's TLS 1.3 suites, no client
/// certificates, `http/1.1` offered by ALPN. A key that does not match
/// the leaf certificate is refused.
///
/// # Errors
///
/// [`TlsError::Cpu`] for a CPU without the provider's features,
/// [`TlsError::KeyMode`] for a key file group or others may access,
/// [`TlsError::Pem`] for a file that cannot be read or holds no
/// certificate or key, and [`TlsError::Rustls`] for a chain or key
/// `rustls` refuses, a mismatched key included.
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
    let key = private_key(key, &pem)?;
    let provider = Arc::new(rustls_graviola::default_provider());
    // The key must match the leaf: checked here, so a mismatch is refused
    // at start, never at the first handshake.
    let certified = rustls::sign::CertifiedKey::from_der(chain, key, &provider)?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// The private key in PEM file `path`, refused when group or others may
/// access the file; the mode is checked on the handle that is read.
fn private_key(
    path: &Path,
    pem: &impl Fn(&Path, String) -> TlsError,
) -> Result<PrivateKeyDer<'static>, TlsError> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path).map_err(|error| pem(path, error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file
            .metadata()
            .map_err(|error| pem(path, error.to_string()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(TlsError::KeyMode(path.display().to_string()));
        }
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| pem(path, error.to_string()))?;
    PrivateKeyDer::from_pem_slice(&bytes).map_err(|error| pem(path, error.to_string()))
}
