<!-- SPDX-License-Identifier: Apache-2.0 -->

# Karyos

Karyos is a low-latency messaging transport written in Rust. Applications
publish and subscribe to message streams through log buffers in shared
memory, managed by a media driver that runs embedded in the application or
as a separate process. Correctness under pauses, crashes and concurrent
writers is designed first and checked with model checking, Miri and a
deterministic simulator. `unsafe` code is confined to the two lowest
crates, and the default build compiles no C.

## Status: 0.1.0-alpha.2

This is an early alpha for evaluation, not for production. APIs, wire
formats, shared-memory layouts and the C ABI will change without notice.
Nothing is published to crates.io.

What the alpha contains:

- **Embedded driver (all platforms).** In-process publication and
  subscription over log buffers: exclusive and concurrent publication,
  claims with a commit deadline, required, optional and observer
  readers with copy delivery, rejoin policies, losing a required
  participant, stream sealing and removal, and mapping generations with
  a cutover.
- **Cross-process IPC (Linux).** Admission of client processes over a
  Unix socket and cross-process data streams over sealed shared-memory
  regions, run by the `karyosd` daemon.
- **UDP transport.** Unicast and multicast channels, reliable and
  unreliable, with lanes, multicast flow control, guards and timed sends
  on the software route. Redundant paths work only in the test rig.
- **Archive and replay.** Recordings, replay and the live merge,
  recording groups with deterministic replay and an output diff, and
  the Archive in `karyosd` with `karyos-catalog` and `karyos-replay`.
  No retention or integrity verification yet.
- **Management.** The local management agent (`karyos-agent`), its
  Prometheus exporter and the operator tools.
- **C ABI.** `libkaryos` at ABI 0.1.1 with a conformance suite. The
  language bindings are not part of this release.
- **Building blocks** for later releases: Cluster foundations (durable
  log, deduplication, snapshots) without a consensus core, a
  deterministic simulator and a benchmark harness.

Supported API: the `karyos` facade, `karyos-client` and `karyos-archive`,
and the C ABI under its own `0.y.z` rule. Every other crate is internal
and unstable in alpha, with no compatibility promise.

Not in this alpha: authenticated or encrypted traffic, `io_uring` and
AF_XDP backends, the ETF route of timed sends, and a replicated Cluster.

The release notes list what works, what does not, and the evidence behind
each claim: [RELEASE-NOTES-0.1.0-alpha.2.md](RELEASE-NOTES-0.1.0-alpha.2.md).

## Platforms

| Platform | What runs | Evidence for this alpha |
| --- | --- | --- |
| Linux, aarch64 | All alpha features, including cross-process IPC, the UDP transport, the Archive in `karyosd` and the conformance suite's Linux scenarios | Docker (`rust:1.99`) on kernel 6.8.0-117-generic aarch64: the workspace tests, the netem tests and the conformance suite with the test kit pass (release notes, Evidence) |
| Linux, x86_64 | All alpha features | Not run for this alpha |
| macOS, arm64 | Embedded driver, the UDP transport and `libkaryos`; cross-process IPC and the Archive daemon are Linux only | Apple M5 Max: `make pre-push`, Loom models, and Miri on `karyos-sys` and `karyos-ffi` pass (release notes, Evidence) |

Docker and virtual machines give functional evidence only. No latency or
throughput figure is claimed for this alpha.

## Build and test

Requirements: the Rust toolchain pinned in `rust-toolchain.toml` (rustup
installs it); Python 3 for the dependency inventory check (`make
deps-check`, part of `make pre-push`); for `make miri`, the nightly
toolchain pinned in the Makefile with its Miri component (`rustup
toolchain install <nightly> --component miri`); and Docker to run the
Linux tests from macOS.

```sh
make test            # cargo test --workspace --locked
make lint            # clippy, warnings denied
make loom            # Loom models of the atomic protocols (karyos-sys)
make miri            # Miri on karyos-sys (pinned nightly in the Makefile)
make sim             # deterministic simulator scenarios
make bench           # benchmark harness (results are indicative only)
make pre-push        # the full local gate
scripts/linux-test.sh                     # cargo test in a Linux container
scripts/linux-test.sh -p karyos-sys --locked  # any cargo test arguments
```

Hosted CI is not running; the gates above are run locally before a merge.

The cross-process control path is exercised by the Linux tests of
`karyos-driver`: `tests/admission.rs` (admission in one process),
`tests/processes.rs` (child processes killed, stopped and restarted) and
`tests/admission_platform.rs` (modes, owners, stale files, backlog, size
seals, descriptor counts):

```sh
scripts/linux-test.sh -p karyos-driver --locked
```

A driver opens its admission socket with `EmbeddedDriver::with_ipc` and
serves it from `do_work`; a client process attaches with
`karyos_client::ipc::attach`. There is no example binary yet.

## Crates

| Crate | Purpose | Status in this alpha |
| --- | --- | --- |
| `karyos-sys` | Shared-memory mappings, atomic views, log buffers, rings, broadcast buffer, counters, conflation table, record journal; one of two crates allowed `unsafe` | Implemented |
| `karyos-protocol` | Frame layouts, flyweights, CnC and admission messages | Implemented for IPC |
| `karyos-client` | Publications, subscriptions, client conductor | Implemented for the embedded driver; remote attach for the control path |
| `karyos-driver` | Driver conductor, embedded driver, admission server | Embedded driver and admission server |
| `karyos-trace` | Trace records, sampling, clock calibration, histograms | Library only, not yet on the data path |
| `karyos-sim` | Deterministic simulator | Implemented for phase 1 scenarios |
| `karyos-bench` | Benchmark harness | Implemented |
| `karyos` | Public facade | Re-exports the client API only |
| `karyos-io`, `karyos-codec`, `karyos-archive`, `karyos-cluster`, `karyos-feed`, `karyos-tools` | Network I/O backends (the other crate allowed `unsafe`), codec, Archive, Cluster, feed arbitration, `karyosd` and tools | Scaffolds for later phases |

## Documentation

The specification, architecture decision records and design documents
live in a separate repository; source comments cite them as
`quantstratum-docs: karyos/<path>`.

## License

Apache License, Version 2.0: see [LICENSE.md](LICENSE.md). Support and
services are offered separately and never restrict the rights the license
grants.
