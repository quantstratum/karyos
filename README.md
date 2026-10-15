<!-- SPDX-License-Identifier: Apache-2.0 -->

# Karyos

Karyos is a low-latency messaging transport written in Rust. Applications
publish and subscribe to message streams through log buffers in shared
memory, managed by a media driver that runs embedded in the application or
as a separate process. Correctness under pauses, crashes and concurrent
writers is designed first and checked with model checking, Miri and a
deterministic simulator. `unsafe` code is confined to the two lowest
crates, and the default build compiles no C.

## Status: 0.1.0-alpha.1

This is an early alpha for evaluation, not for production. APIs, wire
formats and shared-memory layouts will change without notice. Nothing is
published to crates.io.

What the alpha contains:

- **Embedded driver (all platforms).** In-process publication and
  subscription over log buffers: exclusive and concurrent publication,
  claims with a commit deadline, required and optional subscribers with
  copy delivery, stream sealing and removal, and mapping generations with a
  cutover.
- **Cross-process control path (Linux).** Admission of a client process by
  the driver over a Unix socket, with descriptor passing of sealed
  shared-memory regions, a version exchange, the command ring, the
  broadcast buffer and the counters in shared regions, and release of a
  client by its process exit proof. Cross-process data streams are not in
  this alpha (planned for 0.1.0-alpha.2).
- **Building blocks** used by later releases: a keyed conflation table, a
  bounded record journal, trace records, sampling, clock calibration and
  latency histograms, a deterministic simulator and a benchmark harness.

The release notes list what works, what does not, and the evidence behind
each claim: [RELEASE-NOTES-0.1.0-alpha.1.md](RELEASE-NOTES-0.1.0-alpha.1.md).

## Platforms

| Platform | What runs | Evidence for this alpha |
| --- | --- | --- |
| Linux, aarch64 | All alpha features, including the cross-process control path | Docker (TODO(A3): kernel and test counts) |
| Linux, x86_64 | All alpha features, including the cross-process control path | Not yet run for this alpha (TODO(A3)) |
| macOS, arm64 | Embedded driver; cross-process IPC is Linux only | Development host (TODO(A3): Loom and Miri results) |

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
