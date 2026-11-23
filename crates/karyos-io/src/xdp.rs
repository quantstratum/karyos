// SPDX-License-Identifier: Apache-2.0

//! The AF_XDP copy-mode backend (`quantstratum-docs:
//! karyos/design/af-xdp-backend.md`; SPEC.md §16.3), behind the `xdp`
//! feature on Linux.
//!
//! Implemented so far: the prebuilt XDP object of ADR-0038
//! ([`XDP_OBJECT`]), committed with its source (`bpf/karyos-xdp`), its
//! provenance manifest (`src/xdp/karyos_xdp.manifest.toml`) and the
//! notices of the code it contains (`src/xdp/NOTICE`), and its loader
//! over the admitted `aya` (`load`, Linux only). The sockets, UMEM and rings follow
//! in their own issue.

#![forbid(unsafe_code)]

/// The XDP program, built by `scripts/xdp-object.sh` in the pinned
/// container; its SHA-256 is in the manifest beside it. User builds never
/// compile BPF.
pub const XDP_OBJECT: &[u8] = include_bytes!("xdp/karyos_xdp.bpf.o");

/// The program's name in the object.
pub const PROGRAM: &str = "karyos_xdp";

/// The `XSKMAP` keyed by receive queue index.
pub const XSKS_MAP: &str = "xsks";

/// The hash map of the destination endpoints redirected to AF_XDP.
pub const ENDPOINTS_MAP: &str = "karyos_endpoints";

/// The ELF `e_machine` of BPF.
const EM_BPF: u16 = 247;

/// Whether `object` is a little endian 64-bit BPF ELF object, the shape
/// the loader expects; a cheap check before any system call.
#[must_use]
pub fn is_bpf_object(object: &[u8]) -> bool {
    let magic = object.get(..4) == Some(b"\x7fELF".as_slice());
    let class_and_order = object.get(4..6) == Some([2_u8, 1].as_slice());
    let machine = object
        .get(18..20)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_le_bytes);
    magic && class_and_order && machine == Some(EM_BPF)
}

/// Loads [`XDP_OBJECT`] into the kernel: map creation and the verifier,
/// with no attach. Control path only; needs `CAP_BPF` and
/// `CAP_NET_ADMIN`, or `CAP_SYS_ADMIN` (design 5.3).
///
/// # Errors
///
/// The loader's error, for example `EPERM` without the capabilities.
#[cfg(all(feature = "xdp", target_os = "linux"))]
pub fn load() -> Result<aya::Ebpf, aya::EbpfError> {
    let mut ebpf = aya::Ebpf::load(XDP_OBJECT)?;
    let program: &mut aya::programs::Xdp = ebpf
        .program_mut(PROGRAM)
        .ok_or_else(|| aya::EbpfError::ProgramError(aya::programs::ProgramError::NotLoaded))?
        .try_into()
        .map_err(aya::EbpfError::ProgramError)?;
    program.load().map_err(aya::EbpfError::ProgramError)?;
    Ok(ebpf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `sha256` and `size` of the manifest, read as text.
    fn manifest_value(key: &str) -> Option<String> {
        include_str!("xdp/karyos_xdp.manifest.toml")
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key} = ")))
            .map(|value| value.trim_matches('"').to_owned())
    }

    #[test]
    fn the_committed_object_is_a_bpf_object_of_the_manifest_size() {
        assert!(is_bpf_object(XDP_OBJECT));
        assert_eq!(
            manifest_value("size"),
            Some(XDP_OBJECT.len().to_string()),
            "the object and its manifest go together"
        );
        assert!(!is_bpf_object(b"\x7fELF\x02\x01"));
    }

    /// Whether `error` comes from the environment refusing BPF (`EPERM`,
    /// `EACCES` or `ENOSYS` somewhere in its source chain), the only
    /// failure the test may skip: a malformed object, a missing program
    /// or a verifier rejection always fails it.
    #[cfg(all(feature = "xdp", target_os = "linux"))]
    fn environment_denied(error: &aya::EbpfError) -> bool {
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
        while let Some(current) = source {
            if let Some(io) = current.downcast_ref::<std::io::Error>()
                && matches!(io.raw_os_error(), Some(1 | 13 | 38))
            {
                return true;
            }
            source = current.source();
        }
        false
    }

    /// Loads the object through the kernel verifier. Where the
    /// capabilities are missing the test says so and returns, unless
    /// `KARYOS_XDP_REQUIRED` is set.
    #[cfg(all(feature = "xdp", target_os = "linux"))]
    #[test]
    #[expect(
        clippy::print_stderr,
        reason = "a skipped kernel test says why on the test output"
    )]
    fn the_object_passes_the_kernel_verifier() {
        match load() {
            Ok(ebpf) => {
                assert!(ebpf.map(XSKS_MAP).is_some());
                assert!(ebpf.map(ENDPOINTS_MAP).is_some());
            }
            Err(error)
                if std::env::var_os("KARYOS_XDP_REQUIRED").is_none()
                    && environment_denied(&error) =>
            {
                eprintln!("XDP load denied by this environment ({error}); skipped");
            }
            Err(error) => panic!("load: {error}"),
        }
    }
}
