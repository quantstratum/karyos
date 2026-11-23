// SPDX-License-Identifier: Apache-2.0

//! The XDP program of the AF_XDP copy-mode backend (`quantstratum-docs:
//! karyos/design/af-xdp-backend.md` 5.1, AX-2).
//!
//! 1. An untagged IPv4 or IPv6 Ethernet frame goes on; anything else
//!    passes to the kernel.
//! 2. IPv4 with IHL 5, protocol UDP and no fragmentation, or IPv6 with
//!    next header UDP, goes on; anything else passes.
//! 3. A destination address and UDP port found in `karyos_endpoints`,
//!    exactly or as the wildcard of the same family and port, is
//!    redirected to the AF_XDP socket of the receive queue in `xsks`,
//!    falling back to the kernel when the queue has none.
//! 4. Everything else passes. The program never drops, rewrites or
//!    answers a frame.
//!
//! Map ABI: `xsks` is an `XSKMAP` of 64 entries keyed by queue index;
//! `karyos_endpoints` is a hash map of 64 [`EndpointKey`] to `u8`
//! (the value is unused, 1 by convention).

#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{HashMap, XskMap};
use aya_ebpf::programs::XdpContext;

/// The key of `karyos_endpoints`: 20 bytes, no padding.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EndpointKey {
    /// 4 or 6.
    pub family: u8,
    /// Zero.
    pub pad: u8,
    /// The UDP destination port, in network byte order.
    pub port: [u8; 2],
    /// The destination address; IPv4 in the first 4 bytes, the rest zero.
    /// All zero is the wildcard of its family and port.
    pub addr: [u8; 16],
}

#[map(name = "xsks")]
static XSKS: XskMap = XskMap::with_max_entries(64, 0);

#[map(name = "karyos_endpoints")]
static ENDPOINTS: HashMap<EndpointKey, u8> = HashMap::with_max_entries(64, 0);

/// The program's licence, as the kernel reads it: the licence of its
/// source (R8 record, "The program's licence declaration").
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 11] = *b"Apache-2.0\0";

const ETH_HEADER: usize = 14;
const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const ETH_P_IP: [u8; 2] = [0x08, 0x00];
const ETH_P_IPV6: [u8; 2] = [0x86, 0xdd];
const IPPROTO_UDP: u8 = 17;

#[xdp]
pub fn karyos_xdp(ctx: XdpContext) -> u32 {
    match classify(&ctx) {
        Some(key) => redirect(&ctx, &key),
        None => xdp_action::XDP_PASS,
    }
}

/// `N` bytes of the frame at `offset`, bounds checked against the end of
/// the frame as the verifier requires.
#[inline(always)]
fn bytes<const N: usize>(ctx: &XdpContext, offset: usize) -> Option<[u8; N]> {
    let start = ctx.data();
    let end = ctx.data_end();
    let at = start.checked_add(offset)?;
    if at.checked_add(N)? > end {
        return None;
    }
    // SAFETY: `at..at + N` lies inside the frame, checked just above.
    Some(unsafe { core::ptr::read_unaligned(at as *const [u8; N]) })
}

#[inline(always)]
fn classify(ctx: &XdpContext) -> Option<EndpointKey> {
    let ethertype: [u8; 2] = bytes(ctx, 12)?;
    if ethertype == ETH_P_IP {
        let [version_ihl]: [u8; 1] = bytes(ctx, ETH_HEADER)?;
        let [protocol]: [u8; 1] = bytes(ctx, ETH_HEADER + 9)?;
        let fragment: [u8; 2] = bytes(ctx, ETH_HEADER + 6)?;
        // IHL 5, UDP, no MF flag and a zero offset.
        if version_ihl != 0x45 || protocol != IPPROTO_UDP || u16::from_be_bytes(fragment) & 0x3fff != 0 {
            return None;
        }
        let destination: [u8; 4] = bytes(ctx, ETH_HEADER + 16)?;
        let port: [u8; 2] = bytes(ctx, ETH_HEADER + IPV4_HEADER + 2)?;
        let mut addr = [0_u8; 16];
        addr[0] = destination[0];
        addr[1] = destination[1];
        addr[2] = destination[2];
        addr[3] = destination[3];
        return Some(EndpointKey { family: 4, pad: 0, port, addr });
    }
    if ethertype == ETH_P_IPV6 {
        let [next]: [u8; 1] = bytes(ctx, ETH_HEADER + 6)?;
        if next != IPPROTO_UDP {
            return None;
        }
        let addr: [u8; 16] = bytes(ctx, ETH_HEADER + 24)?;
        let port: [u8; 2] = bytes(ctx, ETH_HEADER + IPV6_HEADER + 2)?;
        return Some(EndpointKey { family: 6, pad: 0, port, addr });
    }
    None
}

#[inline(always)]
fn redirect(ctx: &XdpContext, key: &EndpointKey) -> u32 {
    // SAFETY: the map value is only tested for presence, never read
    // through the returned reference.
    let exact = unsafe { ENDPOINTS.get(key) }.is_some();
    let wildcard = EndpointKey { addr: [0; 16], ..*key };
    // SAFETY: as above.
    let matched = exact || unsafe { ENDPOINTS.get(&wildcard) }.is_some();
    if !matched {
        return xdp_action::XDP_PASS;
    }
    XSKS.redirect(ctx.rx_queue_index(), u64::from(xdp_action::XDP_PASS))
        .unwrap_or(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
