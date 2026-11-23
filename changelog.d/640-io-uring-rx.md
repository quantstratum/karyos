### Added

- `karyos-io` feature `uring` (Linux): the `io_uring` RX half `uring::rx::UringRx`, one multishot `IORING_OP_RECVMSG` over a provided buffer ring (`IORING_REGISTER_PBUF_RING`) whose buffers go back to the kernel only after the completion that named them was reaped and lent, reposted when the lend returns or unwinds (karyos#640). Truncated and oversize datagrams are dropped, buffer exhaustion (`-ENOBUFS`) is counted and re-armed, and `reset` cancels the arm and re-registers the pool with every buffer posted once more.
