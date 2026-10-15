// SPDX-License-Identifier: Apache-2.0

//! No descriptor leaks on any transport rejection
//! (`quantstratum-docs: karyos/design/ipc-implementation.md`, i1). One test in its own binary,
//! so that no other test opens or closes descriptors while it counts them.

#![cfg(all(target_os = "linux", not(miri), not(loom)))]
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::IoSlice;
use std::mem::MaybeUninit;

use karyos_sys::error::SysError;
use karyos_sys::ipc::{Recv, Region, RegionKind, RegionRecord, Sent, recv, send, seqpacket_pair};
use rustix::fd::{AsFd, BorrowedFd};
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").map_or(0, Iterator::count)
}

fn record(region: u64) -> RegionRecord {
    RegionRecord {
        instance: 9,
        region,
        kind: RegionKind::Counters,
        generation: 0,
        layout: 1,
        structure_length: 128,
    }
}

fn send_two(socket: BorrowedFd<'_>, pair: [BorrowedFd<'_>; 2]) {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    assert!(control.push(SendAncillaryMessage::ScmRights(&pair)));
    rustix::net::sendmsg(
        socket,
        &[IoSlice::new(b"two")],
        &mut control,
        SendFlags::empty(),
    )
    .unwrap();
}

#[test]
fn every_rejected_datagram_closes_its_descriptors() {
    let first = Region::create(record(1)).unwrap();
    let second = Region::create(record(2)).unwrap();
    let (a, b) = seqpacket_pair().unwrap();
    let mut buffer = [0u8; 16];
    let before = open_fds();
    for _ in 0..50 {
        // Two descriptors in one datagram.
        send_two(
            a.as_fd(),
            [first.descriptor().unwrap(), second.descriptor().unwrap()],
        );
        assert!(matches!(
            recv(b.as_fd(), &mut buffer),
            Err(SysError::Protocol { .. })
        ));
        // A datagram longer than the buffer, with a descriptor.
        assert_eq!(
            send(a.as_fd(), &[1u8; 64], first.descriptor()).unwrap(),
            Sent::Sent
        );
        assert!(matches!(
            recv(b.as_fd(), &mut buffer),
            Err(SysError::Protocol { .. })
        ));
        // An accepted descriptor, then a failed attach: closed as well.
        assert_eq!(
            send(a.as_fd(), b"ok", first.descriptor()).unwrap(),
            Sent::Sent
        );
        let Ok(Recv::Message(received)) = recv(b.as_fd(), &mut buffer) else {
            panic!("no message");
        };
        assert!(Region::attach(received.fd.unwrap(), record(3)).is_err());
    }
    assert_eq!(open_fds(), before);
}
