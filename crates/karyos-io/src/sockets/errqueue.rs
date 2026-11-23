// SPDX-License-Identifier: Apache-2.0

//! Bounded parsing of the control area of one error queue message of an
//! `etf` socket (`quantstratum-docs: karyos/design/timed-tx.md` section 5;
//! the joint `libc` record, "Bounded parsing in safe code"; owner item 29).
//!
//! The control messages are walked in safe Rust over the bytes the kernel
//! wrote, with every length and alignment checked: never the `CMSG_*`
//! pointer helpers and never a cast of the bytes to a struct. A truncated
//! control area (`MSG_CTRUNC`), a `cmsg_len` that does not fit, or an entry
//! of another origin is reported as such and never read past.

#![forbid(unsafe_code)]

/// `SO_EE_ORIGIN_TXTIME` (`include/uapi/linux/errqueue.h`); `libc`
/// 0.2.190 does not define it.
pub const SO_EE_ORIGIN_TXTIME: u8 = 6;
/// `SO_EE_CODE_TXTIME_INVALID_PARAM`.
pub const SO_EE_CODE_TXTIME_INVALID_PARAM: u8 = 1;
/// `SO_EE_CODE_TXTIME_MISSED`.
pub const SO_EE_CODE_TXTIME_MISSED: u8 = 2;

/// `SOL_IP` and `IP_RECVERR`.
const SOL_IP: i32 = 0;
const IP_RECVERR: i32 = 11;
/// `SOL_IPV6` and `IPV6_RECVERR`.
const SOL_IPV6: i32 = 41;
const IPV6_RECVERR: i32 = 25;
/// Bytes of `struct sock_extended_err`.
const SOCK_EXTENDED_ERR: usize = 16;

/// Why the `etf` qdisc dropped a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxtimeCode {
    /// `SO_EE_CODE_TXTIME_INVALID_PARAM`: the time or clock was refused.
    InvalidParam,
    /// `SO_EE_CODE_TXTIME_MISSED`: the time had passed when the qdisc
    /// would have sent it.
    Missed,
    /// Another code of the `TXTIME` origin.
    Other(u8),
}

/// One decoded error queue message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrEntry {
    /// An `etf` drop: the datagram whose `SCM_TXTIME` was `txtime_ns`.
    Txtime {
        /// The requested transmit time of the dropped datagram (the
        /// kernel returns it in `ee_info` and `ee_data`).
        txtime_ns: u64,
        /// Why.
        code: TxtimeCode,
        /// `ee_errno`.
        errno: u32,
    },
    /// An extended error of another origin (for example ICMP), ignored by
    /// the `etf` route.
    OtherOrigin {
        /// `ee_origin`.
        origin: u8,
    },
    /// The control area was truncated (`MSG_CTRUNC`) or held no complete
    /// extended error: the entry cannot be tied to a datagram.
    Truncated,
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn i32_at(bytes: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_ne_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// Bytes of `struct cmsghdr` and the alignment of its data on this
/// target: `cmsg_len` is a `size_t` on Linux.
const ALIGN: usize = core::mem::size_of::<usize>();
const CMSG_HDR: usize = ALIGN + 8;

fn cmsg_align(len: usize) -> Option<usize> {
    len.checked_add(ALIGN - 1).map(|len| len & !(ALIGN - 1))
}

/// Decodes the control area `control` (the first `msg_controllen` bytes)
/// of one error queue message, whose `msg_flags` had `MSG_CTRUNC` set when
/// `truncated`. Returns the first extended error found.
#[must_use]
pub fn parse_control(control: &[u8], truncated: bool) -> ErrEntry {
    if truncated {
        return ErrEntry::Truncated;
    }
    let mut rest = control;
    while rest.len() >= CMSG_HDR {
        let len = match ALIGN {
            8 => rest
                .get(..8)
                .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                .map(u64::from_ne_bytes)
                .and_then(|len| usize::try_from(len).ok()),
            _ => u32_at(rest, 0).and_then(|len| usize::try_from(len).ok()),
        };
        let (Some(len), Some(level), Some(kind)) =
            (len, i32_at(rest, ALIGN), i32_at(rest, ALIGN + 4))
        else {
            return ErrEntry::Truncated;
        };
        if len < CMSG_HDR || len > rest.len() {
            return ErrEntry::Truncated;
        }
        let Some(data) = rest.get(CMSG_HDR..len) else {
            return ErrEntry::Truncated;
        };
        if (level, kind) == (SOL_IP, IP_RECVERR) || (level, kind) == (SOL_IPV6, IPV6_RECVERR) {
            return decode_extended_err(data);
        }
        let Some(next) = cmsg_align(len) else {
            return ErrEntry::Truncated;
        };
        rest = rest.get(next..).unwrap_or_default();
    }
    ErrEntry::Truncated
}

/// Decodes `struct sock_extended_err` field by field.
fn decode_extended_err(data: &[u8]) -> ErrEntry {
    if data.len() < SOCK_EXTENDED_ERR {
        return ErrEntry::Truncated;
    }
    let (Some(errno), Some(&origin), Some(&code), Some(info), Some(high)) = (
        u32_at(data, 0),
        data.get(4),
        data.get(6),
        u32_at(data, 8),
        u32_at(data, 12),
    ) else {
        return ErrEntry::Truncated;
    };
    if origin != SO_EE_ORIGIN_TXTIME {
        return ErrEntry::OtherOrigin { origin };
    }
    let code = match code {
        SO_EE_CODE_TXTIME_INVALID_PARAM => TxtimeCode::InvalidParam,
        SO_EE_CODE_TXTIME_MISSED => TxtimeCode::Missed,
        other => TxtimeCode::Other(other),
    };
    ErrEntry::Txtime {
        txtime_ns: (u64::from(high) << 32) | u64::from(info),
        code,
        errno,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn cmsg(level: i32, kind: i32, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let len = CMSG_HDR + data.len();
        match ALIGN {
            8 => out.extend_from_slice(&(len as u64).to_ne_bytes()),
            _ => out.extend_from_slice(&(len as u32).to_ne_bytes()),
        }
        out.extend_from_slice(&level.to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(data);
        while out.len() % ALIGN != 0 {
            out.push(0);
        }
        out
    }

    fn extended(origin: u8, code: u8, txtime: u64, errno: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&errno.to_ne_bytes());
        data.extend_from_slice(&[origin, 0, code, 0]);
        data.extend_from_slice(&(txtime as u32).to_ne_bytes());
        data.extend_from_slice(&((txtime >> 32) as u32).to_ne_bytes());
        data
    }

    #[test]
    fn a_txtime_drop_is_decoded_with_its_time_and_code() {
        let txtime = 0x0001_2345_6789_abcd;
        let control = cmsg(
            SOL_IP,
            IP_RECVERR,
            &extended(SO_EE_ORIGIN_TXTIME, SO_EE_CODE_TXTIME_MISSED, txtime, 62),
        );
        assert_eq!(
            parse_control(&control, false),
            ErrEntry::Txtime {
                txtime_ns: txtime,
                code: TxtimeCode::Missed,
                errno: 62
            }
        );
        let v6 = cmsg(
            SOL_IPV6,
            IPV6_RECVERR,
            &extended(SO_EE_ORIGIN_TXTIME, SO_EE_CODE_TXTIME_INVALID_PARAM, 7, 22),
        );
        assert!(matches!(
            parse_control(&v6, false),
            ErrEntry::Txtime {
                code: TxtimeCode::InvalidParam,
                txtime_ns: 7,
                ..
            }
        ));
    }

    #[test]
    fn origin_type_and_truncation_are_told_apart() {
        // Another origin (ICMP is 2).
        let icmp = cmsg(SOL_IP, IP_RECVERR, &extended(2, 3, 0, 111));
        assert_eq!(
            parse_control(&icmp, false),
            ErrEntry::OtherOrigin { origin: 2 }
        );
        // Another control message type before the error is skipped.
        let mut two = cmsg(1, 37, &[0; 8]);
        two.extend(cmsg(
            SOL_IP,
            IP_RECVERR,
            &extended(SO_EE_ORIGIN_TXTIME, SO_EE_CODE_TXTIME_MISSED, 9, 62),
        ));
        assert!(matches!(
            parse_control(&two, false),
            ErrEntry::Txtime { txtime_ns: 9, .. }
        ));
        // MSG_CTRUNC, a short extended error and a cmsg_len past the end.
        let full = cmsg(
            SOL_IP,
            IP_RECVERR,
            &extended(SO_EE_ORIGIN_TXTIME, SO_EE_CODE_TXTIME_MISSED, 9, 62),
        );
        assert_eq!(parse_control(&full, true), ErrEntry::Truncated);
        let short = cmsg(SOL_IP, IP_RECVERR, &[0; 8]);
        assert_eq!(parse_control(&short, false), ErrEntry::Truncated);
        assert_eq!(
            parse_control(&full[..full.len() - 4], false),
            ErrEntry::Truncated
        );
        assert_eq!(parse_control(&[], false), ErrEntry::Truncated);
    }

    proptest! {
        #[test]
        fn any_control_area_parses_without_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256), truncated in any::<bool>()) {
            let _ = parse_control(&bytes, truncated);
        }
    }
}
