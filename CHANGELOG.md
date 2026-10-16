<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to Karyos are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0 any
release may break APIs, wire formats and shared-memory layouts.

## [Unreleased]

### Changed

- The admission `Manifest` carries the stream position where the fetched
  mapping starts (its base), within admission protocol version 2. A remote
  client maps a grant at that base, so its positions, loss reports and
  trace records are absolute stream positions after a guard close and
  reopen, as an in-process handle's are.
- `EmbeddedDriver::guard_stream` refuses with
  `DriverError::GuardWalkerUnavailable { stream, reason }` when the stream's
  walker, which holds one spare-slot credit for the stream's life, finds no
  credit (`WalkerUnavailable::NoSpareCredit`) or no reader cell
  (`WalkerUnavailable::NoReaderCell`).
- Driver positions are absolute stream positions after a guard close and
  reopen: `EmbeddedDriver::seal_state` reports the current mapping's base
  plus its seal (`DriverError::PositionsExhausted` past the position
  range), and a revoked required participant's loss record names the base
  of its incarnation plus its cell position.

### Added

- `karyos_driver::guard_gate::GuardGate`, the sender gate of a guarded
  publication's lanes (G-e2): one Acquire load of the guard word per
  check, `Aborting` and the applied epoch published once per incarnation,
  a between gates step, and the publication's authoritative token bucket,
  shared by its lanes, whose tokens are reserved at exposure and refunded
  for a head that left unsent; a head it cannot pay for is held in order
  (`GateCounts::rate_held`, not a fault).
- `karyos_io::lanes::LaneGate::flushing` and `LaneGate::left` (default
  no-ops) and `Left`: the sender names the lane it flushes before each
  flush and reports each head that left its queue to its gate.
- `karyos_sys::rate_limit::RateLimiter::admits` (a check that charges
  nothing), `refill_at`, `refund`, and their datagram forms
  (`admits_datagram`, `try_admit_datagram`, `refund_datagram`) for a
  datagram that starts several messages.
- Rate limits of guarded publications (G-e3, GC-5):
  `EmbeddedDriver::guard_stream` takes an optional `GuardRate` (a `RateScope`
  and a `RatePolicy`), refuses scopes other than `RateScope::Publication`
  (`DriverError::RateScopeUnsupported`) and policies that fail validation
  against the stream's MTU, which bounds every datagram
  (`DriverError::InvalidRatePolicy`). Every handle bound to the guard keeps a
  copy of the message bucket (`GuardBinding::with_rate`), and `offer` and
  `try_claim` return the new `OfferOutcome::RateLimited` and
  `ClaimOutcome::RateLimited` while it holds no token, appending nothing
  (retry later; nothing is dropped). A claim that is never sent gives its
  token back. The copy rejects early what the sender gate would hold at that
  instant; the gate's bucket is authoritative, but until the network agents
  wire it the copy is the only limiter in practice. The copy can be stricter
  than the gate: a message accepted and later aborted keeps its charge, and so
  does a claim leaked with `mem::forget`. A sealed handle reports its seal
  before the copy is asked.
- The effective-close acknowledgement (G-e4):
  `EmbeddedDriver::register_guard_sender` and `deregister_guard_sender` keep a
  bounded registry of sender gates (`DriverConfig::max_guard_senders`,
  `DriverError::TooManyGuardSenders`), and `EmbeddedDriver::close_guard_ack`
  reports each one `Applied` (positions and work in flight) or `Pending`,
  overdue past `DriverConfig::guard_ack_timeout` and never reported closed; a
  close is effective at a sender once applied with nothing in flight.
  `karyos_sys::applied_epoch::Applied` carries `in_flight`, published by the
  gate with its applied epoch and again as the work drains.
- `karyos_sys::schedule_ring` (P2.11 T1, TT-1): the schedule ring of a timed
  lane, one entry (first-frame position and requested time) per message in a
  power-of-two ring, written by the exclusive publisher (room checked with the
  head loaded Acquire before reservation, the entry then the tail with Release
  before the commit) and read by the sender (the tail with Acquire, the head
  released with Release); counts never wrap. Modelled with Loom (a read before
  the commit retries and never takes a stale entry), with negative controls
  for a commit before its entry, a Relaxed head load and a head released
  before the read. Not yet mapped into a log buffer's region.
- The log buffer region carries a timed lane's schedule ring (P2.11 T1,
  TT-1): `LogBufferConfig::schedule_capacity` (0 for a lane that is not timed,
  which gets no ring words; otherwise a power of two on an exclusive
  publication), a configuration block word, and a schedule section before the
  terms, initialised at creation and read through `LogBuffer::schedule_ring`.
  The region layout version is 3; regions of versions 1 and 2 are refused at
  attach with `SysError::LayoutVersion`.
- Timed offers (P2.11 T1, TT-2, TT-3): `ClientPublication::offer_at` sends a
  message of a timed lane with its requested not-before time, after checks
  made before anything is reserved (a time below the lane's last is
  `ClientError::InvalidSchedule`, one beyond the horizon `ScheduleTooFar`, an
  overflowing deadline `ScheduleOverflow`, a full schedule ring
  `BackPressured`); plain `offer` and `try_claim` are refused on a timed lane,
  and `offer_at` on another. `karyos_client::schedule` holds `ClockDomain`
  (`Monotonic`, and `Tai` on Linux through the new
  `karyos_sys::host_clock::host_tai_ns`), `now(domain)` and `ScheduleOptions`
  (provisional defaults: 1 s horizon, 1 ms tolerance);
  `EmbeddedDriver::schedule_stream` sets them before any handle
  (`DriverError::NotTimed` for a lane that is not timed), and a CnC
  publication of a timed lane is refused for now, as is a cutover
  (`DriverError::TimedCutover`), a zero horizon, and new settings once a
  handle of the incarnation was issued. A schedule clock that cannot read
  the time returns `schedule::CLOCK_UNAVAILABLE` and the offer is refused
  with `ScheduleOverflow`. In karyos-sys, `Publication::append_scheduled`
  pushes the message's schedule entry after its reservation and before its
  commit store through the publication's own publisher of its own ring,
  refuses a time below the last (`ScheduleError::Backwards`) and observes a
  seal before a full ring's back pressure; `Publication::schedule_has_room`
  reports the ring's room (`SysError::Schedule`). A
  schedule capacity is a power of two up to `schedule_ring::MAX_CAPACITY`
  (2^20), refused otherwise with `ScheduleError::Capacity`, and attach checks
  the ring's own capacity word against the configuration.
- Timed head eligibility (P2.11 T1 step 4): `ScheduleReader` reads ahead
  with a private cursor (`peek`, `advance`) and `release` frees entries in
  order, never past it (`ScheduleError::Invariant`). In karyos-driver,
  `schedule::ScheduleConsumer` gives each frame of a timed lane its
  message's requested time and releases the entry once the message left;
  `timed_gate::TimedGate` wraps a lane gate, holds a head until its time and
  passes only the due prefix of an exposure to the inner gate, its permit
  the minimum of the two.
- Cancel-on-deadline (P2.11 T1 step 5, G7): `TimedGate` takes a
  `LatePolicy` per lane (tolerance, `cancel_on_deadline`). Under cancel, a
  head not exposed by its time plus the tolerance aborts the lane for good
  (`deadline_missed`, counted once in `deadline_aborts`), and
  `TimedGate::between_gates` seals its buffer once through
  `timed_gate::seal_deadline_missed` (`SealReason::DeadlineMissed`; a sealed
  buffer keeps its first reason). Otherwise a head submitted beyond the
  tolerance counts in `late_sends`. The inner gate is not told, but a lane
  it already aborts never misses: karyos-io's `LaneGate` gains
  `aborting(lane)` (default false; `GuardGate` reports its aborting
  incarnations), so a guard close that lands first stays the lane's end
  (G7). `TimedGate::earliest` also wakes for a deadline under cancel,
  `TimedGate::stage` takes the datagram's ticket and `left` counts a report
  for another ticket as a fault, and `ScheduleConsumer::new` takes its
  capacity from the ring (`ScheduleReader::capacity`).
- Timed counters and an injected schedule clock (P2.11 T1 step 6). Public
  API additions in karyos-client: `schedule::ScheduleClock` (the clock a
  timed lane's offers are checked against, the host clock of the domain by
  default; it runs on the offer path and must not allocate or block, and
  returns `CLOCK_UNAVAILABLE` when it cannot read the time),
  `ScheduleCounters`, `ScheduleBinding::with_counters` and
  `ClockDomain::label`; `ScheduleBinding::new` takes a `ScheduleClock`. In
  karyos-driver, `EmbeddedDriver::schedule_stream_with_clock` and
  `timed_counters`. When a timed lane's first handle is issued the driver
  allocates its counters (key0 the stream, key1 the lane, the clock domain
  in each label): `timed scheduled offers`, `timed rejections` invalid, too
  far, overflow and ring full, `timed late sends`, `timed deadline aborts`
  and an 8 cell lateness histogram (`timed_gate::LATENESS_LABELS`), which a
  `TimedGate` counts into once given them (`attach_counters`). In
  karyos-sys, `Publication::append_scheduled` now returns
  `ScheduledOutcome`: an append's `AppendOutcome`, or `ScheduleFull` for a
  full ring, so a full ring is counted exactly.
- Timed simulator scenarios (P2.11 T1 step 6): `timed-send-late` and
  `timed-cancel` in karyos-sim's `tests/timed.rs`, 40 seeds each, drive a
  timed stream on virtual time through `ScheduleConsumer` and `TimedGate`
  over the scripted sockets, with an immediate lane beside it. They check
  that nothing is submitted before its time, that order holds, that the
  immediate lane is never held, and that a miss under cancel seals
  `DeadlineMissed` with nothing submitted after it. karyos-sim takes
  karyos-io (with its test hooks) as a dev-dependency. In karyos-driver,
  `EmbeddedDriver::schedule_ring` and `seal_deadline_missed`.
- Redundant paths at the receive owner (P2.9, redundant-paths.md sections
  4 and 5, ACS 15519): `karyos_driver::paths` with `PathConfig`
  (`max_paths`, `path_queue_datagrams`, `skew_sample_frames`,
  `path_skew_window` validated in 0 to 1 s), `skew::SkewDeadline` (fixed at
  detection, no window below two live paths, the larger of reorder and skew
  on unreliable channels), `queues::PathQueues` (bounded per path, drops
  counted per path, served round robin) and `stats::PathStats` (wins,
  duplicates, stale replays, conflicts, per-path `Late`, missing bytes per
  whole term of a binding from fresh deliveries only, arrival differences
  from a ring of first arrivals per lane, and freshness per path for path
  liveness, the mark seeded at the path's join and kept across a loss).
- Redundant path bindings at the receiver (P2.9, redundant-paths.md
  sections 2 and 3, ACS 15519): `sessions::paths::PathBindings` binds an
  image's first path at installation and later paths of the same identity,
  alias, term parameters and lane count through their own challenge (RP-1:
  their joins are recorded, never applied); a path's liveness takes only
  fresh evidence and PATH_HB, and a lost path leaves no tombstone. The
  receive sessions answer a later path with `AnswerOutcome::PathBound`,
  with no image created and no conductor chain reserved, refuse a full
  image (`Ignored::PathsFull`), and keep refusing an identity challenged or
  answered under another key. `SessionConfig` gains `max_paths` and
  `path_liveness_timeout`. The path rows decide admission: `lookup` and
  the bound-key checks go through them, so a first path lost at its
  timeout stops admitting and returns only through a fresh challenge, as a
  later path. `ReceiveSessions::timers` removes lost paths within
  `timer_actions`. Not wired yet: refreshing a path on fresh DATA and
  PATH_HB intake, which phase 5c calls through `paths_mut()`.
- RTT observations (P2.7 B, reliable-transport.md, RC-1, ACS 15597):
  `karyos_driver::rtt::RttProbes` probes each path of an image with at most
  one outstanding RTTM REQUEST (random nonzero 64-bit ids from
  `ProbeIds`, the operating system's in the driver, so an off-path
  spoofer cannot forge a reply; a failed draw is counted),
  samples only submitted probes from the time read before the submitting
  call to the validated reply, never subtracts `service_delay_ns`, raises a
  sample below `rtt_floor` to it, refuses a zero sample, keeps the largest
  of the last `rtt_sample_window` samples as the path's estimate
  (`rtt_initial` before any or after a rebinding) and gives NAK timing the
  largest estimate over the live paths (`snapshot`). A path whose binding
  generation is exhausted stops probing and is counted, never wrapped.
  `RttReplies` limits a sender's replies to `rttm_reply_rate` per second
  per source endpoint, in a bounded table of `rttm_reply_sources`, so one
  source cannot starve the others (ACS 15618).
- Multicast receiver membership and flow control (P2.7 A,
  multicast-flow-control.md, MC-1 to MC-9, ACS 15597, 15604 and 15610):
  `karyos_driver::membership::Membership`, one publication incarnation's
  receiver table, owned by its sender agent. It takes SMs the session
  binding validated (`SmKey`) and keys members by `receiver_id` and
  `receiver_boot_id`, with a checked generation per slot (`MemberRef`,
  `current`) and retired slots at exhaustion. A member records up to
  `max_paths` bindings, so one receiver over several paths stays one
  member; `binding_gone` removes a binding, and the last one removes the
  member (a required one is lost, M5; ACS 15636). Roles and tags are
  configured (`Roles`): a mismatched `group_tag` rejects the SM, and a
  required receiver has one membership per incarnation. The join fixes
  each lane's window in `min_window..=max_window`; a changed window, a
  stale or impossible consumption (above `sent_high`) or an overflowing
  edge rejects the whole SM. An SM is fresh when it advances a lane or
  reports `sent_high` on every lane; a stationary member lives until
  `pause_timeout` (default 60 s), counted as `stationary` and `paused`.
  `limit` gives a lane's edge (the strategy's extremum, `min`, `max` or
  `tagged`, then the minimum with every live required edge),
  `NoReceiverWindow` or `Held`. `admission` opens once the required set
  has joined and stops for good at a required loss, whose last consumption
  stays in `retention`. An expired optional member leaves a tombstone: it
  rejoins only with an SM fresh against its last consumption or after a
  new `expect`, so stationary SMs cannot defeat `pause_timeout` (ACS
  15647). `timers` expires members within a bound with a fair
  cursor, and membership events are queued in a bounded queue. Not wired
  yet: the sender agent's SM handoff and gate.

## [0.1.0-alpha.1]: 2026-10-15

First alpha: the embedded driver on every supported platform and the
cross-process control path on Linux. See
[RELEASE-NOTES-0.1.0-alpha.1.md](RELEASE-NOTES-0.1.0-alpha.1.md).

### Build and tooling

- Cargo workspace on Rust edition 2024 with a pinned toolchain, a denied
  lint set inherited by every crate, and `forbid(unsafe_code)` outside
  `karyos-sys` and `karyos-io`.
- Local gates: `make pre-push` (format, lint, documentation, tests, Loom,
  release build), Miri on a pinned nightly, the dependency inventory check,
  and `scripts/linux-test.sh` for Linux tests in Docker.

### Shared memory and log buffers (`karyos-sys`)

- Term identity, slot descriptors, loans with the reclaim and revocation
  handshakes, and atomic-only views over heap and sealed shared-memory
  backings.
- Frame geometry, term memory and an embedded log buffer with exclusive
  publication, rotation, slot reuse and copy delivery to subscribers.
- Claims with a commit deadline that aborts a stuck claim.
- Concurrent publication: tails, derived head, credits, handles, claims,
  rotation by concurrent publishers and the commit-deadline abort.
- Sealing a publication; mapping generations with the concurrent fence and
  a cutover.
- Counters with seqlock metadata, the broadcast buffer, the SPSC command
  ring, a keyed conflation table and a bounded record journal with loss
  accounting.
- Term backings over heap and shared terms, with atomic-word access only
  for shared terms.

### Protocol (`karyos-protocol`)

- Frame header, frame types, the trace extension and message sizing; a
  sequential term appender and scanner.
- CnC command and response messages; admission socket messages with a
  version exchange.

### Client and embedded driver (`karyos-client`, `karyos-driver`)

- Embedded API: offer, poll with copy delivery, and the driver's duty cycle.
- Command path for the embedded mode, stream removal and reclamation, and
  driver counters.
- Claims through the client, the claim deadline in the duty cycle and
  counters for every deadline result.
- Concurrent publication through the client and through client commands.
- Stream removal seals the buffer; client handles follow a mapping
  generation cutover driven by the driver.

### Cross-process IPC (Linux)

- Shared-memory regions and descriptor passing.
- The command ring, the broadcast buffer and the counters in shared
  regions.
- Process exit proof through pidfd.
- The log buffer over a shared region, validated in `karyos-sys`.
- The admission server and remote client attach: admission over the Unix
  socket with a version exchange, a bounded connect, the per-client command
  ring, broadcast responses and read-only counters in sealed regions,
  `Leave`, retirement, release by the exit proof, and a driver restart that
  keeps the old mappings. At start the driver removes a file at its socket
  path only if it is a socket of the driver's uid with mode 0600 that
  refuses connections; anything else (a regular file, a symlink, a socket
  of another owner or mode, or a live driver's socket) is kept and the
  start fails. A stale socket that matches the rule is removed even if it
  belonged to something else.

### Tracing (`karyos-trace`)

- Trace observation records and a typed trace journal, loss attribution to
  traces, sampling, clock calibration with latency intervals, and latency
  histograms. Not yet connected to publication and subscription.

### Simulation and benchmarks

- A deterministic simulator for phase 1 scenarios and a benchmark harness.
