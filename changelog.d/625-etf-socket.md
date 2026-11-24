### Added

- The `etf` route's socket layer in `karyos-io` (karyos#625, first part): `sockets::etf::EtfSocket`, a dedicated UDP socket with `SO_TXTIME` on `CLOCK_TAI` and error reports, sending each datagram with `SCM_TXTIME`; `sockets::errqueue`, bounded parsing of the error queue's control area in safe code (origin, code and truncation told apart, the dropped datagram named by its time); and `linux_sys`, the one module calling `libc` (`recvmsg` with `MSG_ERRQUEUE`), under the joint Linux `libc` record. A real `etf` qdisc drop is decoded with its own time. The driver's `etf` route follows.
