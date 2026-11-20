// SPDX-License-Identifier: Apache-2.0

//! The TLS provider's CPU requirements, checked at start (the agent HTTP
//! stack's admission record, condition 5): `graviola` asserts them at its
//! first operation, so a CPU without them would panic there. The component
//! refuses to start instead.

/// Why the TLS provider cannot run here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CpuError {
    /// The CPU lacks a feature the provider requires.
    #[error("the CPU lacks `{0}`, which the TLS provider requires")]
    Missing(&'static str),
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
/// [`CpuError::Missing`] with the first feature missing.
pub fn check() -> Result<(), CpuError> {
    match features().into_iter().find(|(_, present)| !present) {
        Some((name, _)) => Err(CpuError::Missing(name)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    /// The development and CI hosts have the provider's features.
    #[test]
    fn this_cpu_runs_the_provider() {
        assert_eq!(super::check(), Ok(()));
    }
}
