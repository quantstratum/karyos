<!-- SPDX-License-Identifier: Apache-2.0 -->

# Karyos 0.1.0-alpha.1 release notes

An early alpha for evaluation. It is not for production use, and nothing
in it is published to crates.io. APIs, wire formats and shared-memory
layouts will change.

## What works

- **Embedded driver**, on Linux and macOS: publication and subscription in
  one process over log buffers.
  - Exclusive publication (`offer`, `try_claim`) and concurrent
    publication from several handles.
  - Claims with a commit deadline: a stuck claim is aborted and its readers
    skip it.
  - Required subscribers, which bound the publisher and are never lapped,
    and optional subscribers, which are lapped and rejoin at the head with
    the lost range reported.
  - Copy delivery: a handler always reads a private copy, so a slow
    handler never pins shared memory.
  - Stream removal, publication seal, and mapping generations with a
    cutover that client handles follow.
  - Driver counters, read in process.
- **Cross-process control path**, on Linux:
  - Admission of a client process over the driver's Unix socket, with
    credential and process exit checks.
  - A protocol version exchange; an incompatible pair is refused before
    any mapping.
  - Sealed shared-memory regions passed as descriptors: the client's
    command ring, the broadcast buffer and the counters.
  - Release of a client and its resources by the process exit proof
    (pidfd).
  - TODO(A2): confirm against the merged admission server and remote
    client.
- **Libraries** for later releases, usable directly: the keyed conflation
  table, the bounded record journal, trace records, sampling, clock
  calibration and latency histograms, the deterministic simulator and the
  benchmark harness.

## What does not work yet

- **Cross-process data streams.** A publication or subscription in another
  process than the driver, which needs the log buffer hand-over between
  processes: planned for 0.1.0-alpha.2.
- **Planned for 0.1.0-alpha.2 in the embedded mode as well:** the observer
  reader role, the `snapshot` and `close` rejoin policies, losing a
  required participant (heartbeats and the `hold`, `continue` and `abort`
  policies), conflated subscriptions, tracing on the data path, and
  per-stream observability, the error log and the operational tools
  (`karyosd`, `karyos-stat`, `karyos-errors`).
- **Later phases:** UDP transport, network I/O backends, lanes, guards,
  timed transmission and wire security; Archive and replay; Cluster.
- **No performance claim.** The benchmark harness exists, but no latency or
  throughput figure is published for this alpha.

## Known limitations

- Cross-process IPC is Linux only. On macOS IPC is embedded, in one
  process.
- A process with write access to the driver's directory or mappings is
  outside the isolation boundary; deployment permissions must prevent that
  access.
- Liveness heartbeats are not implemented: a paused client keeps its
  resources until it exits or detaches.
- Shared-memory regions are writable by every admitted process; read-only
  tool access does not exist yet.
- Hosted CI is not running; the gates are run locally.
- TODO(A3): limitations found by the process tests.

## Evidence

Functional evidence only. Docker and virtual machines say nothing about
latency on physical hosts.

| Check | Environment | Result |
| --- | --- | --- |
| `make pre-push` (format, lint, docs, tests, Loom, release build) | TODO(A5): host, OS and architecture | TODO |
| `make miri` (`karyos-sys`, nightly-2026-10-11) | TODO(A5): host | TODO |
| `make loom` | TODO(A5): host | TODO |
| `make sim` (seeds) | TODO(A5): host and seed count | TODO |
| `scripts/linux-test.sh` (workspace tests in Docker) | TODO(A3): kernel and architecture printed by the script | TODO: pass and skip counts |
| Cross-process control process tests (exit proof after a kill, a stopped client kept charged, driver restart, platform checks) | TODO(A3): kernel and architecture | TODO(A3) |
| Linux x86_64 | Not run for this alpha | Not claimed |

## Upgrading

There is no earlier release. Expect breaking changes in 0.1.0-alpha.2.
