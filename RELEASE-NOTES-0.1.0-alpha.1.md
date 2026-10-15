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
    (pidfd): a killed client is released, a stopped one keeps its slot
    and resumes, and a restarted driver starts a new instance while the
    old mappings stay valid for clients that hold them.
  - Entry points: `EmbeddedDriver::with_ipc` and `do_work` on the driver
    side, `karyos_client::ipc::attach` on the client side. There is no
    example binary yet; the Linux tests of `karyos-driver` are the
    runnable evidence.
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
- A listening socket that was just closed can stay held by a process
  forked at that moment until it calls `exec` (close-on-exec acts only at
  `exec`), so a restarted driver's listen may be refused briefly; the
  tests retry for up to 2 s.
- A thread pidfd must not count as an exit proof. On the kernel tested
  (6.8), `pidfd_open` rejects the `PIDFD_THREAD` flag with `EINVAL`, so
  only that fallback was exercised; Karyos's own refusal of a real thread
  pidfd needs kernel 6.9 or later, which was not run.

## Evidence

Commit ids marked "legacy" name commits of the pre-migration
history, kept in the private legacy repository; the others are
commits of this repository.

Functional evidence only. Docker and virtual machines say nothing about
latency on physical hosts.

Rows with a commit are historical evidence for that commit, recorded
during development; the release-gates rows are the final run on `3c9de47`,
the release content: the tagged commit adds only these notes and the
changelog date on top of it.

| Check | Commit | Environment | Result |
| --- | --- | --- | --- |
| Miri, `karyos-sys` library tests (nightly-2026-10-11) | `legacy 438f0cc` | macOS arm64, Apple M5 Max | 306 of 306 pass, no undefined behaviour reported |
| Miri, region adoption tests | `b8165eb` | macOS arm64, Apple M5 Max | 10 of 10 pass |
| Region tests after the Linux-only kind check | `4be1f09` | Docker, kernel 6.8.0-117-generic aarch64 | 4 of 4 pass; no full Miri rerun after it |
| `make loom` | `553f873` | macOS arm64 (Darwin 27.0.0), Apple M5 Max, rustc 1.99.0 | 15 suites, 64 passed, 0 failed, 0 ignored |
| `scripts/linux-test.sh` (`cargo test --workspace`) | `553f873` | Docker `rust:1.99` (rustc 1.99.0), kernel 6.8.0-117-generic aarch64 (colima VM) | 591 passed, 0 failed, 0 ignored, including the `karyos-sys` library tests (340), admission (6), platform (11) and process (4) tests |
| Process tests (`karyos-driver/tests/processes.rs`: a killed client released by its exit proof, a stopped client kept charged then resumed, a driver restart that keeps the old mappings readable) | `4dbb003`, merged as `553f873` | Docker, kernel 6.8.0 aarch64 | 4 of 4 pass, five consecutive runs |
| Platform tests (`karyos-driver/tests/admission_platform.rs`: modes, owners, stale and foreign files, backlog, size seals, descriptor counts) | `1f7d080` on `ad8c1e9` | Docker as root, kernel 6.8.0-117-generic aarch64 | 11 of 11 pass, three consecutive runs |
| Release gate `make pre-push` (fmt, lint sync, dependency checks, clippy, rustdoc, workspace tests, Loom, release build) | `3c9de47` | macOS arm64 (Darwin 27.0.0), Apple M5 Max, rustc 1.99.0 | pass: 613 tests passed, 0 failed, 0 ignored |
| Release gate `make miri` (`karyos-sys` library tests, nightly-2026-10-11) | `3c9de47` | macOS arm64 (Darwin 27.0.0), Apple M5 Max | 318 of 318 pass, no undefined behaviour reported; the Linux-only `ipc` module is not compiled on macOS and is not covered by Miri |
| Release gate `make sim` (2000 seeds per scenario) | `3c9de47` | macOS arm64 (Darwin 27.0.0), Apple M5 Max, rustc 1.99.0 | 7 of 7 scenarios pass |
| Release gate `scripts/linux-test.sh --workspace --locked` | `3c9de47` | Docker `rust:1.99` (rustc 1.99.0), kernel 6.8.0-117-generic aarch64 (colima VM) | 601 passed, 0 failed, 0 ignored |
| Linux x86_64, kernels 6.9 and later | none | Not run for this alpha | Not claimed |

## Upgrading

There is no earlier release. Expect breaking changes in 0.1.0-alpha.2.
