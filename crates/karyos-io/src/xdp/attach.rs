// SPDX-License-Identifier: Apache-2.0

//! The XDP attachment of one interface (`quantstratum-docs:
//! karyos/design/af-xdp-backend.md` 5.1 and 5.2, AX-4): loads the
//! committed object with `aya`, fills `karyos_endpoints`, attaches in the
//! configured mode and sets `xsks[queue]` after each bind.
//!
//! - **Explicit mode.** [`AttachMode::Generic`] or [`AttachMode::Native`],
//!   from configuration, never inferred and never `XdpMode::Default`.
//! - **Link only, never replace.** Only a `bpf_link` attachment is kept:
//!   `aya` falls back to a netlink attach on old kernels, which would
//!   survive a crash, so a netlink kind is refused and detached. A link
//!   never replaces another program: attach fails while one is attached.
//! - **Detach.** Dropping the attachment drops its link, which detaches
//!   only Karyos's own program.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use aya::maps::{HashMap, MapData, XskMap};
use aya::programs::Xdp;
use aya::programs::links::FdLink;
use aya::programs::xdp::{XdpLink, XdpMode};

use super::{ENDPOINTS_MAP, PROGRAM, XDP_OBJECT, XSKS_MAP};

/// The configured attach mode (`xdp-attach`, AX-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachMode {
    /// Generic XDP (`XdpMode::Skb`): any netdev, after the kernel builds an
    /// skb.
    Generic,
    /// Native XDP (`XdpMode::Driver`): a driver with XDP support.
    Native,
}

/// Why the attachment failed.
#[derive(Debug)]
pub enum AttachError {
    /// Loading, the verifier or a map call failed.
    Load(aya::EbpfError),
    /// The program could not be attached in the configured mode.
    Program(aya::programs::ProgramError),
    /// A map update failed.
    Map(aya::maps::MapError),
    /// `aya` attached through netlink, not `bpf_link`: refused and
    /// detached (AX-4).
    NotALink,
    /// A map or the program is missing from the object.
    Missing(&'static str),
}

impl std::fmt::Display for AttachError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Load(error) => write!(f, "xdp load failed: {error}"),
            Self::Program(error) => write!(f, "xdp attach failed: {error}"),
            Self::Map(error) => write!(f, "xdp map update failed: {error}"),
            Self::NotALink => f.write_str("xdp attached through netlink, not bpf_link; refused"),
            Self::Missing(what) => write!(f, "xdp object has no {what}"),
        }
    }
}

impl std::error::Error for AttachError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Load(error) => Some(error),
            Self::Program(error) => Some(error),
            Self::Map(error) => Some(error),
            Self::NotALink | Self::Missing(_) => None,
        }
    }
}

/// The 20-byte `karyos_endpoints` key of `address` (the program's
/// `EndpointKey`): family, a zero pad byte, the port in network order, the
/// address (IPv4 in the first 4 bytes).
#[must_use]
pub fn endpoint_key(address: SocketAddr) -> [u8; 20] {
    let mut key = [0_u8; 20];
    let (family, bytes): (u8, [u8; 16]) = match address {
        SocketAddr::V4(v4) => {
            let mut bytes = [0_u8; 16];
            let octets = v4.ip().octets();
            for (target, source) in bytes.iter_mut().zip(octets) {
                *target = source;
            }
            (4, bytes)
        }
        SocketAddr::V6(v6) => (6, v6.ip().octets()),
    };
    key[0] = family;
    key[2..4].copy_from_slice(&address.port().to_be_bytes());
    key[4..20].copy_from_slice(&bytes);
    key
}

/// The program attached to one interface and its maps.
#[derive(Debug)]
pub struct XdpAttachment {
    // The link first: dropping it detaches before the maps go.
    link: Option<FdLink>,
    ebpf: aya::Ebpf,
}

impl XdpAttachment {
    /// Loads the object, lists `endpoints` in `karyos_endpoints`, and
    /// attaches the program to `ifindex` in `mode` as a `bpf_link`.
    ///
    /// # Errors
    ///
    /// [`AttachError`]; nothing stays attached.
    pub fn attach(
        ifindex: u32,
        mode: AttachMode,
        endpoints: &[SocketAddr],
    ) -> Result<Self, AttachError> {
        let mut ebpf = aya::Ebpf::load(XDP_OBJECT).map_err(AttachError::Load)?;
        {
            let map = ebpf
                .map_mut(ENDPOINTS_MAP)
                .ok_or(AttachError::Missing(ENDPOINTS_MAP))?;
            let mut map: HashMap<&mut MapData, [u8; 20], u8> =
                HashMap::try_from(map).map_err(AttachError::Map)?;
            for endpoint in endpoints {
                map.insert(&endpoint_key(*endpoint), &1, 0)
                    .map_err(AttachError::Map)?;
            }
        }
        let program: &mut Xdp = ebpf
            .program_mut(PROGRAM)
            .ok_or(AttachError::Missing(PROGRAM))?
            .try_into()
            .map_err(AttachError::Program)?;
        program.load().map_err(AttachError::Program)?;
        let mode = match mode {
            AttachMode::Generic => XdpMode::Skb,
            AttachMode::Native => XdpMode::Driver,
        };
        let id = program
            .attach(ifindex, mode)
            .map_err(AttachError::Program)?;
        let link: XdpLink = program.take_link(id).map_err(AttachError::Program)?;
        // A netlink kind is refused; dropping the error's link detaches it.
        let link = FdLink::try_from(link).map_err(|_| AttachError::NotALink)?;
        Ok(Self {
            link: Some(link),
            ebpf,
        })
    }

    /// Sets `xsks[queue]` to `socket` after its bind.
    ///
    /// # Errors
    ///
    /// [`AttachError::Map`].
    pub fn set_socket(&mut self, queue: u32, socket: &impl AsRawFd) -> Result<(), AttachError> {
        let map = self
            .ebpf
            .map_mut(XSKS_MAP)
            .ok_or(AttachError::Missing(XSKS_MAP))?;
        let mut xsks: XskMap<&mut MapData> = XskMap::try_from(map).map_err(AttachError::Map)?;
        xsks.set(queue, socket.as_raw_fd(), 0)
            .map_err(AttachError::Map)
    }

    /// Clears `xsks[queue]`: new packets of that queue pass to the kernel
    /// (design 11.2 step 3).
    ///
    /// # Errors
    ///
    /// [`AttachError::Map`].
    pub fn unset_socket(&mut self, queue: u32) -> Result<(), AttachError> {
        let map = self
            .ebpf
            .map_mut(XSKS_MAP)
            .ok_or(AttachError::Missing(XSKS_MAP))?;
        let mut xsks: XskMap<&mut MapData> = XskMap::try_from(map).map_err(AttachError::Map)?;
        xsks.unset(queue).map_err(AttachError::Map)
    }

    /// Whether the attachment holds its link.
    #[must_use]
    pub fn is_linked(&self) -> bool {
        self.link.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_keys_match_the_program_layout() {
        let v4 = endpoint_key("10.1.2.3:4660".parse().unwrap());
        assert_eq!(&v4[..4], &[4, 0, 0x12, 0x34]);
        assert_eq!(&v4[4..8], &[10, 1, 2, 3]);
        assert!(v4[8..].iter().all(|byte| *byte == 0));
        let v6 = endpoint_key("[fd00::1]:1".parse().unwrap());
        assert_eq!(&v6[..4], &[6, 0, 0, 1]);
        assert_eq!(v6[4], 0xfd);
        assert_eq!(v6[19], 1);
    }
}
