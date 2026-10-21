<!-- SPDX-License-Identifier: Apache-2.0 -->

# Karyos 0.1.0-alpha.2 release notes

An early alpha for evaluation. It is not for production use, and nothing
in it is published to crates.io. APIs, wire formats, shared-memory
layouts and the C ABI will change.

This alpha adds cross-process data streams on Linux, the UDP transport,
the Archive with replay and recording groups, the management agent and
its tools, and a C ABI with a conformance suite. It holds 2133 commits
since 0.1.0-alpha.1 (TODO: recount at the release head). No phase of the
delivery plan is complete: each section below says what is covered and
what is partial.

## Supported API

The supported API of this alpha is the `karyos` facade, `karyos-client`
and `karyos-archive`, and the C ABI under its own `0.y.z` rule. Every
other crate (`karyos-sys`, `karyos-protocol`, `karyos-codec`,
`karyos-io`, `karyos-trace`, `karyos-driver`, `karyos-cluster`,
`karyos-feed`, `karyos-agent`, `karyos-tools`, `karyos-bench`,
`karyos-sim`, and the Rust items of `karyos-ffi`) is internal to the
workspace and unstable in alpha, with no compatibility promise; each
says so in its crate documentation.

## What works

### IPC

- **Cross-process data streams**, on Linux: a publication or a
  subscription in another process than the driver's, over log buffers
  granted at admission.
  - A forgotten claim of a remote publisher is aborted at its next call,
    and a stopped required subscriber back-pressures the publisher
    (`karyos-driver/tests/processes.rs`).
  - Remote subscriptions, publications and concurrent publications
    follow a mapping cutover without allocating, and a stopped
    subscriber never delays it (`karyos-driver/tests/remote_cutover.rs`).
  - A remote client's registrations are capped at
    `max_exports_per_client`; the images it read are freed once no grant
    holds them.
  - A stream configured `allow_unconnected` grants it to remote clients
    too (`karyosd --stream <id>:<session>:allow-unconnected`).
- **Losing a required participant**: a silent client times out at its
  liveness timeout, and the `hold`, `continue` and `abort` policies
  revoke it, in process and across processes
  (`karyos-driver/tests/liveness.rs`, `processes.rs`).
- **Reader roles and rejoin policies**: the observer role, and the
  `at head`, `close` and `snapshot` rejoin policies, with the exact lost
  range reported (`karyos-driver/tests/rejoin.rs`). The `replay` policy
  recovers a gap from an Archive (below).
- **Conflated views across processes**: `Client::add_conflated_subscription`
  reads a remote stream's conflation table, and every publication checks
  its key against the table before it appends (`ClientError::Conflation`).
  `karyosd --conflation` gives a configured stream a table.
- **Stall isolation.** Optional readers and an observer that hold loans
  never back-pressure a publisher: in one process, with a network
  sender's reader kept up and its retention hold
  (`karyos-sys/src/log_buffer_tests/observer.rs`), and across processes,
  with paused reader processes holding their copies' loans while a
  publisher process runs ten terms (`karyos-driver/tests/processes.rs`,
  `test_ipc_stall_isolation_paused_optional_and_observer_processes_never_hold_the_publisher`).
  Across processes the publisher can see short `BACK_PRESSURED` stretches
  from the per-cycle limit, each ending within two conductor cycles; a
  paused required reader does hold it, as specified.
- **Partial: required set transitions.** The limit follows the required
  set and never decreases under `hold`, `continue` and `abort`; no test
  runs the transition with a required recording as the only required
  participant.

### Network transport

- **UDP channels** (`karyos:udp`), unicast and multicast, reliable and
  unreliable, in an embedded driver, on an IPC driver, and in `karyosd`
  with `--network on` (tested through two `karyosd` processes on
  loopback).
  - Under netem loss, reorder and duplicates
    (`make netem`, `crates/karyos-driver/src/net/e2e/netem.rs`): an
    unreliable channel delivers each message at most once and in order
    and reports every loss as a gap (N1); a reliable channel delivers
    every message exactly once and in order through NAKs and repairs,
    also with two lanes, multicast, a 500 ms blackout and between two
    IPC drivers (N2 to N8).
  - Multicast flow control with the `min` strategy, and required
    receivers that bound the sender; RTT measurement; NAK admission
    against the retention floor, coalesced repair jobs and a bounded
    repair scheduler. A channel URI with `fc=max` or `fc=tagged` is
    refused as an unsupported channel rather than run as `min` (karyos#617):
    the `max` and `tagged` strategies exist only inside the driver and its
    tests, with no public way to request them yet.
  - A slow optional receiver no longer holds a reliable publisher: the
    floor is held at `sent - retransmit_window` while the required
    receivers allow it.
  - Challenge lifecycle, alias collision (every image of an alias is
    exposed, keyed by its source) and one driver holding both ends of a
    `karyos:udp` endpoint.
  - A network subscription's ready reply carries its bound address
    (IPv4, or IPv6 with its scope; a multicast subscription's group and
    bound port), exposed as `Subscription::bound_address()`; an image's
    source address uses the same encoding (karyos#612, #615).
  - Aborts and fragmented aborts over the network reach a remote reader
    as one extent and are repaired, never NAKed past.
- **Lanes**: per-lane deficit round robin with fairness bounds, and
  bounded per-cycle work with no allocation in a steady cycle.
- **Guards**: a guarded network publication stops at a close (a local
  close on trusted channels; nothing more leaves the sender), records
  each message `Submitted`, `Unknown` or `Aborted`, reports the
  effective-close acknowledgement, enforces a per-publication rate limit,
  and takes a fresh incarnation on the wire after a reopen. A publisher
  in another process binds its guard and reads its outcome records
  (`karyos-driver/tests/guarded_remote.rs`).
- **Timed sends** on the software route: no datagram before its
  requested time, on unreliable and reliable channels, and for a timed
  publisher in another process, whose breach of the schedule ring seals
  the lane and retires the client
  (`karyos-driver/src/net/e2e/timed.rs`,
  `karyos-driver/tests/network_processes.rs`).
- **Partial: redundant paths.** Covered in the test rig with per-path
  socket isolation assumed: one routed publication over several paths,
  repair on every live path, path liveness, receive queues per path and
  the EOS on every live path. On real sockets a channel with `paths` is
  refused (see "What does not work yet").
- **Conflation freshness for network images.** A lost update marks the
  view's values stale, and each key turns fresh again with its own next
  update. Refresh and snapshot markers are a separate capability (below).

### Archive and replay

- **Recordings**: a segment store with CRC-32C checked writes and
  durable positions, an append-only catalog, `required` recordings that
  throttle the publisher and `async` ones that record a lap as a gap.
  Recovery at every crash point keeps the durable prefix
  (`crates/karyos-archive/src/segment/tests.rs`,
  `every_crash_point_recovers_the_durable_prefix`).
- **Replay**: a recording replayed into a target stream, paced as
  recorded or scaled; the live merge of a replay into a live
  subscription at an explicit cutover; and the `replay` rejoin, which
  recovers an overrun's gap from an Archive and merges it back
  (`karyos-sim/tests/archive_control.rs`).
- **Recordings across a mapping cutover**: a lagging recording drains to
  the seal and continues with no gap; a paused one is fenced without
  delaying the cutover, and an `async` one rejoins at the head
  (`karyos-sim/tests/archive_cutover.rs`).
- **Recording groups and the Gateway**: a group's journal, its three
  prefixes and its checkpoints; capture of every observation as the
  handler saw it, strict or best effort; replay through
  `ReplayGateway`, isolated from a running driver; and the output diff,
  `karyos-replay diff`. Phase 3's functional gate items are covered:
  torn-write and restart, complete and durable common-prefix recovery,
  exact captured observations, the output diff and isolation of external
  effects, with one minor test gap tracked as an issue: no test shows
  that the first of several differences is the one reported.
- **The Archive in the daemon and its tools**, on Linux: `karyosd
  --archive`, `--archive-control`, `--record` and `--archive-min-free`;
  `karyos-catalog list`, offline and `--live`; `karyos-replay start` and
  `stop` (`karyos-tools/tests/karyosd_archive.rs`, `karyosd_catalog.rs`,
  `karyosd_replay.rs`).

### Management agent and tools

- **`karyos-agent`**: attaches to drivers as a tool and serves API v1 as
  JSON on a local Unix socket, to the uids of a role table (viewer,
  operator, risk officer, administrator).
  - Lag, loss, guard acknowledgement and journal gap alerts.
  - A trace latency window per lane, reported as intervals, never as
    verdicts.
  - Audited guard operations (`guard-close`, `guard-reopen`, `gap-ack`)
    with an operations journal kept as an Archive recording.
  - The Archive catalog of a watched driver (`--archive`).
- **`karyos-exporter`**: the agent's view in the Prometheus text format,
  on a loopback address only.
- **CnC counters for tools**: per-stream network counters, each network
  endpoint's capabilities (logged by `karyosd` at startup), spin time per
  idle loop, guard state, the guard audit ring and close
  acknowledgements; `karyos-stat` shows the per-stream counters.
- **Partial: audited operations.** Local guard operations are covered
  end to end through the socket; purge, standby promotion, replicated
  closes and authenticated operators are not there.

### C ABI and conformance suite

- **`libkaryos`** (`crates/karyos-ffi`, `include/karyos.h`), ABI version
  0.1.1: clients, embedded drivers, exclusive and concurrent
  publications, staged claims, subscriptions with roles and rejoin
  policies, guarded publications' outcome records, timed offers and
  clocks, conflated views, and an Archive's catalog, replays and
  Archive-backed rejoin.
  - Every message reaches a handler from a private copy, never a shared
    mapping.
  - The thread rules of each handle kind are in `karyos.h`: a concurrent
    call on one handle is refused with `KARYOS_E_BUSY`, never
    serialized.
  - Each `karyos_*_init` fills at most the caller's struct.
- **Packaging for evaluation**: `make libkaryos` (headers, static and
  shared libraries, `karyos.pc` and `karyos-static.pc`, a MANIFEST), and
  `make libkaryos-testkit` for the suite's Linux scenarios. The package
  is unsigned.
- **Conformance suite** (`crates/karyos-ffi/conformance/`, formats 1
  and 2, run by `tests/conformance.rs`): typed statuses, use after close,
  double close, struct sizes of other minors, the reentrant and bounded
  polls, claims, and the features `archive-replay`, `remote-driver` and
  `incompatible-driver` (Linux). TODO: scenario count at the release
  head.
- **Partial: C ABI boundary.** The protocol and panic rows are not yet
  scenarios, the kept fragment pointer row is covered by a Rust test
  only, and there is no older-minor manifest before a first released
  header.

### Tracing

- **Network trace points**: sender and receiver journals per lane,
  opened by the conductor's trace hook, with each receiver commit and
  the first 16 sealed gaps of each traced lane.
- **Partial: journal loss attribution.** Loss is attributed end to end
  through real journals and the trace report; the late hardware TX
  timestamp is not.

### Libraries for later releases

- Cluster foundations, tested without a consensus core: the durable
  Raft log and vote store with prefix purge, the replicated session
  table for request deduplication, and the snapshot store, with crash
  tests on the simulator's disk.
- Simulator harnesses for membership changes and a standby cluster,
  run against a reference fixture with a fixed leader.

## What does not work yet

- **Authenticated and encrypted traffic.** Only the `trusted` security
  profile exists; `authenticated` and `encrypted` are refused when a
  channel is parsed, and `GUARD`, `SESSION_ABORT` and
  `SESSION_ABORT_ACK` are not decoded. Authenticated traffic releases
  under its own capability gate (ADR-0076), and the authenticated cases
  of receiver restart freshness, stale datagrams after a sender restart
  and the abort acknowledgement move there. The `encrypted` class is a
  separate optional capability.
- **Conflation refresh and snapshot markers**, a separate capability:
  a stale conflated value turns fresh only when it is replaced.
- **Network backends other than sockets**: no `io_uring` or AF_XDP
  backend and no zero-copy TX.
- **The `etf` route of timed sends** (`SO_TXTIME`) and hardware launch
  time, which is refused at configuration. A timed network publication
  also refuses redundant paths, the `Tai` domain and cancel-on-deadline.
- **Redundant paths on real sockets**: a channel with `paths` is refused
  while the sockets cannot be isolated per path, and unicast `paths` are
  refused.
- **Multi-destination unicast and SBE framing**: not implemented.
- **Cluster** (phase 4): no consensus core. Raft commitment,
  linearizability under faults, snapshot install and replicated guards
  wait on the core selection.
- **Archive retention and integrity**: no sealing, anchors, verifier,
  legal hold or purge, and no `karyos-catalog verify`. `--archive-min-free`
  is the only bound on disk use.
- **Bindings**: the language bindings are frozen and are not part of
  this release. `libkaryos` is packaged for evaluation only.
- **Management**: no console, no remote or authenticated API, no OTLP,
  no sealed operations journal, no recording control or guard operator
  API over the C ABI. Container images, Helm chart, Terraform modules
  and marketplace listings do not exist.
- **Issues after the tag.** Defects reported after the release head are
  tracked as issues of the core repository and are not listed here.
- **No performance claim.** `karyos-bench` records Archive append and
  sync costs, but no gate reads them and no latency or throughput figure
  is published for this alpha.

## Known limitations

- Cross-process IPC is Linux only. On macOS a driver runs embedded, and
  `karyos_client_connect` answers `KARYOS_E_UNSUPPORTED`.
- A process with write access to the driver's directory or mappings is
  outside the isolation boundary; deployment permissions must prevent
  that access. The Archive's trust boundary is the daemon's uid: every
  admitted client may control it.
- A remote client maps the regions only the driver writes (its outcome
  ring, its guard words and the counters) read only. The log buffer
  regions of a stream stay writable by every client admitted to it, as
  the loan and position protocol requires, so the admission rules bound
  who can write them.
- Hosted CI is configured, but its jobs do not start (no step runs), so
  the gates are run locally; the Evidence table records them.
  TODO(M8): re-check at the release head.
- The netem tests are `#[ignore]` and run only through
  `scripts/netem-test.sh`; several multicast tests are Linux only and
  return early when the host's multicast probe fails.
- Timed sends need a network publication. A driver's local or IPC
  stream refuses a schedule ring (`schedule_capacity` above 0) with
  `InvalidConfig`, `KARYOS_E_INVALID_ARGUMENT` from the C ABI: nothing
  there would release it (karyos#614). A client gets timed network
  publications by URI on the streams `karyosd --timed-network` names, at
  most 8. No timed lane uses the `Tai` domain: the network route refuses
  it, and local streams refuse schedule rings. A `Monotonic` lane is
  granted only to a client in the driver's time namespace.
- A conflated view closed at `barrier_ack_timeout` is recreated with
  every key stale; no test asserts that recreation yet, and
  `barrier_ack_timeout` is checked only against its 10 ms floor, not
  against the conductor's duty period. Both are tracked as issues.
- A unicast subscription on port 0 is refused; a bound ephemeral port
  for a subscription follows in a later release.
- A replay replays lane 0 only, and a network publication refuses a
  mapping cutover.
- `karyosd --network on` runs the agents with the default network
  configuration; the rest is not on the command line.
- A signal stop of `karyos-agent` is recorded as an unclean stop and
  opens a journal gap.
- A handle of another static copy of `libkaryos` in the same process is
  normally refused with `KARYOS_E_CLOSED`. That defends against
  accidental misuse only: two copies whose generation bases are equal, or
  whose slots' generation counts drift apart by the bases' difference,
  accept each other's handles. It is no security boundary.
- A listening socket that was just closed can stay held by a process
  forked at that moment until it calls `exec`, so a restarted driver's
  listen may be refused briefly; the tests retry for up to 2 s.
- A thread pidfd must not count as an exit proof. Karyos's refusal of a
  real thread pidfd needs kernel 6.9 or later, which was not run.
- The `test-hooks` Cargo features of `karyos-sys` (`test_pause`,
  `alloc_count`, fault injectors) and `karyos-io`
  (`sockets::scripted`) are test support for this workspace's tests, not
  public API: they carry no compatibility promise and are never enabled
  outside dev-dependencies here.

## Evidence

Functional evidence only. Docker and virtual machines say nothing about
latency on physical hosts.

The rows with a head other than the release head are historical
evidence for that commit, recorded during development by the author and
the reviewer of each change. The release-gates rows are run at tagging
on the release head; the tagged commit adds only these notes and the
changelog date on top of it.

| Check | Platform | Head | Result |
| --- | --- | --- | --- |
| `scripts/linux-test.sh --workspace --all-features --locked` | Docker `rust:1.99`, kernel 6.8 aarch64 | `38ccc6d7` | 117 suites, 3193 passed, 0 failed, 15 ignored |
| `scripts/netem-test.sh` (`loss 2% reorder 10% 50% delay 1ms duplicate 1%`) | Docker, kernel 6.8 aarch64 | `38ccc6d7` | 9 passed, 0 failed |
| `scripts/linux-test.sh`, `make pre-push`, `loom_schedule_ring` | Docker (Linux run); kernel not recorded | `9faba3ee` | 117 suites, 3320 passed, 0 failed; pre-push green; 11 of 11 |
| `scripts/linux-test.sh`, clippy, `make pre-push` | Docker (Linux run), aarch64; kernel not recorded | `05b628e1` | 151 suites, 0 failed; clippy clean; pre-push green |
| Release gate `make pre-push` | macOS arm64 | TODO | TODO |
| Release gate `make miri` (`karyos-sys` and `karyos-ffi`, per `crates/karyos-ffi/MIRI.md`) | macOS arm64 | TODO | TODO |
| Release gate `make loom` | macOS arm64 | TODO | TODO |
| Release gate `make sim` | macOS arm64 | TODO | TODO |
| Release gate `scripts/linux-test.sh --workspace --all-features --locked` | Docker `rust:1.99`, kernel TODO aarch64 | TODO | TODO |
| Release gate `make netem` | Docker, kernel TODO aarch64 | TODO | TODO |
| Release gate `make libkaryos`, `libkaryos-static-check`, `libkaryos-copies-check` | macOS arm64 and Linux aarch64 | TODO | TODO |
| Release gate conformance suite with the test kit (`archive-replay`, `remote-driver`, `incompatible-driver`) | Linux aarch64 | TODO | TODO |
| Linux x86_64, kernels 6.9 and later | none | Not run for this alpha | Not claimed |

## Upgrading

Nothing is compatible with 0.1.0-alpha.1 across a process boundary or
on disk:

- The admission protocol is version 2; alpha.1 used version 1.
- The log buffer layout is version 5; regions of earlier versions are
  refused at attach.
- Public enums decoded from evolving wire and record schemas, the
  channel URI enums and the public error enums of the library crates are
  `#[non_exhaustive]` (karyos#613, #616): a match outside the crate needs
  a wildcard arm, and an unknown value is refused with a typed error,
  never given another meaning. `GroupGateway` is sealed. Public report
  structs of `karyos-client` and `karyos-archive` are built through
  constructors.
- The `karyos` facade moved 13 re-exports from `karyos::` to
  `karyos::embedded::` (`ClientConductor`, `ClientPublication`,
  `ClientSubscription`, `ClientClaim`, `OfferOutcome`, `ClaimOutcome`,
  `CommitOutcome`, `Completion`, `ConductorError`, `ConductorPoll`,
  `Outcome`, `Overrun`, `Aborted`): change the `use` paths. `karyos::Error`
  gains the `Offer` and `Subscription` variants.
- The C ABI is new in this release, at version 0.1.1. A caller accepts
  exactly the `0.y` it targets with at least its minimum `0.y.z`.

Expect breaking changes in the next alpha.

