<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to Karyos are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0 any
release may break APIs, wire formats and shared-memory layouts.

## [Unreleased]

### Changed

- `karyos-archive` gains its recorder and agent (phase 3, A4b). A
  `Recorder` copies a lane's committed frames from a `FrameSource` into
  its recording's segment store: data, a padding or aborted block as a
  fill, a lost range as a gap. `Mode::Required` throttles the publisher
  when the disk stalls (SPEC section 8.1); `Mode::Async` records a lap as a gap
  and stops there or resumes where its source rejoins. The
  `ArchiveHandle` agent thread owns the catalog and the recorders, settles
  the catalog at start, and stops each recording in the catalog once its
  store is closed with everything durable (`SegmentStore::close_synced`,
  whatever the policy), at the durable position. A source that fails or
  returns what a source never may ends its recording with
  `StopReason::Failed(FailKind)`; a store that fails leaves it open for
  the next start to settle (`Event::Failed { failure }`). A command stop,
  the shutdown and the seal record `Stopped`, `Shutdown` and `Normal`.
  Dropped events are counted (`ArchiveHandle::dropped_events`). A store
  records at most `MAX_GAPS` lost ranges; an async recording lapped past
  them ends `Lapped`. The catalog format becomes version 2.
- The Archive's segment index entries have a kind (phase 3, A4): data, a
  fill (a padding or aborted block's canonical record, covering its
  extent) or a gap (a range an async recording lost, refused to reads).
  `SegmentStore::append_fill`, `append_gap` and `gaps`; an unknown kind is
  refused at recovery. The catalog's stop gains the reason `Lapped` and an
  `incomplete` flag, which `settle` sets for a recording with gaps. The
  `Disk` trait's `truncate` becomes `set_len`, which also extends.
- `karyos-archive` gains its catalog (phase 3, A3): `catalog.kyc`, an
  append-only log of CRC-32C checked records (a recording started,
  stopped or forgotten, and the id watermark), each durable before the
  call returns. Ids are never reused: a compaction, written to a temporary
  file and renamed over the catalog, carries the watermark. Opening cuts a
  torn log and removes a compaction's leftover; `Catalog::settle` stops the
  recordings a crash left open at their recovered position, with the
  reason recorded. The `Disk` trait moves to `karyos_archive::disk` and
  gains `rename`.
- `karyos-archive` gains its segment store (phase 3, A2): a recording's
  positions in segment files of a checked multiple of the term length, each
  with an index of CRC-32C checked writes; written and durable positions,
  with data then index synced before `durable` advances; no-sync,
  per-segment and interval policies; and recovery that keeps every whole,
  checked write in order and reports where it cut. Syncs are `fdatasync` on
  Linux and `F_FULLFSYNC` on Apple targets (through the standard library),
  and a new segment's directory entry is synced on Linux. A table-driven
  CRC-32C (`karyos_archive::crc32c`) needs no dependency. Recovery removes
  only a last segment whose header is missing or torn (being created);
  any other bad header is `SegmentError::BadHeader` and removes nothing.
  The interval policy syncs a finished segment at its next tick, never on
  the write path.
- A conflated network view closes on its own. Its image retiring publishes
  the terminal reason `TERMINAL_IMAGE_RETIRED` (4) with an empty interval;
  exhausted versions or a feeder that cannot read on publish
  `TERMINAL_FRESHNESS_EXHAUSTED` or the new `TERMINAL_FEEDER_LOST` (5), and
  the image lane stays open for its other subscribers.
  `NetworkViewCounters` splits `unbuilt` into `unbuilt_unexposed` and
  `unbuilt_failed` with `last_build_failure` (`ViewBuildFailure`), and adds
  `closed_retired` and `feeders_lost`. A view's configuration is also found
  for an image on a subscription's later path.
- `ViewClosed` maps reason 4 to `ImageRetired { since: None }` and reason 5
  to the new `FeederLost { since }`.
- A conflation reader that sees its table closed reads the terminal cell
  again, so a terminal published before the close is in that poll's
  report. `ConflationWriter::seed_version` is available to dependent
  crates' tests under `test-hooks`.
- `AgentConfig::control_capacity` defaults to 512 (was 256). Configuration
  now refuses a receiver control ring below `max_pending_challenges +
  max_images × max_paths + 32`, since an image's SM goes on each of its
  bound paths (redundant paths, RP-7).
- The receiver counts its control copies on redundant paths:
  `ReceiverCounters::sm_copies`, `sm_copies_skipped`, `nak_copies`,
  `nak_copies_skipped` and `nak_copies_uncertain`.

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
- Documented image admission: at the default `ImageTemplate::spare_slots`
  of 5, each image lane admits one optional or observer reader, since the
  receive owner holds three of its four spare-slot credits; another is
  refused with `ResourcesUnavailable`. Raising `spare_slots` by one admits
  one more, at one term per lane of image storage.
- Driver positions are absolute stream positions after a guard close and
  reopen: `EmbeddedDriver::seal_state` reports the current mapping's base
  plus its seal (`DriverError::PositionsExhausted` past the position
  range), and a revoked required participant's loss record names the base
  of its incarnation plus its cell position.

### Added

- The live set of a routed publication's paths (redundant-paths.md section
  7, RP-8; rp-w5a). Each path keeps a `path_lag_limit` window (100 ms) of
  bytes selected and skipped: one that skipped anything is `Degraded`, and
  one whose skipped share passes `path_skip_ratio` (50%, once
  `path_skip_min_bytes`, 64 KiB, were selected), or that the lane waited on
  alone for longer than `path_lag_limit`, leaves the live set while another
  path remains (`AgentConfig::path_policy`, validated at start). A path out
  of it takes no copy and no flush and holds no head back
  (`RoutedLaneSender::set_live`); its never-exposed copies come back
  (`RoutedLaneSender::cancel_route`) through the guard gate; those it held
  alone are counted (`PathCounters::copies_abandoned`) and reach receivers
  by NAK or close as gaps. `Outbound::path_state` and
  `Outbound::path_counters` report it. A faulted route leaves too, while
  another path is live.
- A left path returns (RP-9; rp-w5b) after its backoff
  (`PathPolicy::backoff_initial`, 10 ms, doubling to `backoff_max`, 1 s
  and at most `MAX_PATH_BACKOFF`, 60 s, and starting over after
  `backoff_reset`, 10 s, live): on its open queue,
  or by `retry_queue` after a fault, from the current selection point,
  counted (`PathCounters::entries`). It bounds `Outbound::sent_low`, the
  least frontier over the live paths, from its first submit; a frame a
  path skipped counts as passed for its frontier.
- A close no longer waits on a detached path (rp-w5b; ACS 17049). On a
  guarded lane's abort, the copies of a route whose TX half is detached
  are forgotten through the guard gate (`RoutedLaneSender::forget`), so
  the close can become effective if the path never comes back, and counted
  (`RouteCounters::forgotten`). The route then returns only through an
  endpoint reset.
- Receiver trace journals keep their sealed gaps (P2.12 step 3, PR 3b,
  trace-network.md section 5): the first `FACT_GAP_INTERVALS` (16) gaps of
  each traced lane, in order, with an overflow flag, carried in
  `JournalFacts::gaps`. `EmbeddedDriver::network_journal_gaps` returns a
  closed receiver journal's gaps for an in-process report.
  `SkipPolicy::duty_observed` and `range_unavailable_observed` tell a
  callback of each committed seal; `duty`, `duty_gated`,
  `range_unavailable` and `range_unavailable_gated` delegate to them.
- Network publications over redundant paths (rp-w4b2c): a multicast IPv4
  channel with `paths` sends on one endpoint per path, each bound to its
  path's interface address, as one routed publication; each path holds its
  send endpoint and the receiver's published alias, released and retired
  with the publication. Refused with `DriverError::UnsupportedChannel`, and
  counted, while the sockets cannot be isolated per path
  (`SocketOps::isolates_paths`, owner item 12); unicast `paths` stay
  refused (owner item 11).
- The sender over a routed publication's paths (redundant-paths.md, rp-w4b2b):
  a SETUP side on each path's endpoint, established on any path; SMs, NAKs
  and bindings found on any path (`Outbound::serves`,
  `Outbound::destination_on`); and a PATH_HB on each path idle for
  `AgentConfig::path_heartbeat_interval` (default 100 ms, an interim for the
  channel heartbeat interval RP-3 names), counted by
  `SenderCounters::path_heartbeats_sent`. `SendSessions::identity` gives a
  session's incarnation. A routed publication takes one entry of
  `AgentConfig::publications` per path.
- The conductor hands network trace hooks and journals to the agents
  (P2.12 step 3, PR 3a). `set_network_trace_hook` gives the hook to its
  side's agent; a journal opens per lane of a publication once the sender
  added it and of an image once it is installed, including those already
  there when a hook is set. The agent's start and close facts go to the
  trace mirror. A publication's sender journals close before the sender
  removes it, and an image's when it retires. `CloseNetworkJournal` names
  the journal number, so a stale close never answers a later journal of a
  reinstalled identity. A journal the agent refuses is closed and counted
  as refused; one a hook change closes is counted in the new driver counter
  `network trace journals unhooked`.
- Receiver network trace points (P2.12 step 3, trace-network.md section 4,
  section 5, NT-2 to NT-4). The receiver agent writes one journal per lane
  of an installed image: `OpenNetworkJournal` starts it at the lane's next
  commit position (the image join fact); a traced DATA frame records one
  `ReceiverCommit` when it commits, naming its path (a repair that fills a
  hole records too), and copies of an already committed frame record
  nothing; `CloseNetworkJournal` answers the
  start, the lane's resolved prefix as the commit boundary and its first
  sealed gap. An image that retires closes its lanes' journals at once and
  posts their facts as `NetworkJournalClosed`, retried while the event ring
  is full; a later close answers the same facts once. New receiver counters:
  `net_trace_ext_invalid` and `net_journals_retired_dropped`.
- Conflated views of network images (conflated-network-images.md, C4).
  `EmbeddedDriver::add_network_subscription_conflated` names the lane and
  the view's `ConflationConfig`. When the image of such a key is exposed,
  the conductor builds a heap table over the image's `FreshnessLink`, feeds
  it from a required subscription of the lane and attaches it to the
  mailbox. Each duty the feeder first records a gap met in the log (held,
  and nothing past it polled, while the barrier is full), then serves the
  seal request, acknowledging only after the loss is recorded (withheld
  while full), writes values with their positions (`write_at`) and
  reconciles in bounded passes. A published terminal cell closes the feeder.
  `EmbeddedDriver::network_view_counters` reports `NetworkViewCounters`:
  views built and not built, acknowledgements given and withheld, gaps
  recorded from the log, views closed by their terminal cell.
- The receiver gates a conflated network image lane's seals
  (conflated-network-images.md, C3). `AddSubscription` carries the
  conflated lane (driver-internal entry
  `EmbeddedDriver::add_network_subscription_conflated`; subscriptions sharing
  a receiver entry agree on it, `DriverError::ConflationMismatch`). At
  install the receiver allocates the image's `FreshnessLink`, hands it to the
  conductor with `ImageInstalled` (`ImageTable::freshness`) and seals that
  lane through a gate over its barrier mailbox: at once while no feeder is
  attached, after the feeder's acknowledgement once one is, and past
  `AgentConfig::barrier_ack_timeout` (default 100 ms, at least 10 ms) after
  publishing the view's terminal cell, waiting while a feeder's claimed cell
  is unpublished. New receiver counters: `seals_gated`, `barrier_posts`,
  `barrier_acks`, `seals_unattached`, `barrier_timeouts`,
  `barrier_claim_waits`, `barrier_post_failures` and
  `conflated_lane_out_of_range`.
- Conflation freshness for network images' views (conflated-network-images.md,
  C2): `conflation_fresh` builds a heap table with a loss barrier over the
  terminal cell of a `FreshnessLink` (a seal mailbox and a terminal cell in
  one allocation, shared with the image's receive owner). Its writer
  records a loss (`record_loss`, refused below the frontier with the
  terminal cell published, or while the ring is full), writes values with
  their freshness (`write_at`, `FreshSlotWords::write_with_freshness`),
  reconciles the slots in bounded passes and retires the records
  (`reconcile`), and counts the work (`FreshCounters`). It refuses a value
  without its position (`ConflationError::PositionRequired`) or below its
  frontier (`ConflationError::BehindFrontier`), and a terminal close also
  closes the table. The reader
  classifies each copied value against the barrier and the terminal cell:
  `ConflationReader::poll_changed`'s handler gets the `Freshness` as a
  fourth argument, a new loss serves every written key again, and after the
  terminal cell nothing is delivered (`PollReport::terminal`). Terminal
  reasons are `TERMINAL_BARRIER_TIMEOUT`, `TERMINAL_FRESHNESS_EXHAUSTED` and
  `TERMINAL_BELOW_FRONTIER`. Tables without a barrier deliver every value
  Fresh; the client's `ConflatedSubscription` keeps its signatures.
- `karyos_io::lanes::routes::RoutedLaneSender`: one DRR over a lane's
  queues on up to `MAX_ROUTES` routes (redundant-paths.md section 7,
  RP-10). A lane's head is selected once, submitted on every route that
  holds it at its front, and debited once; `catch_up` sends the copies of
  routes that fell behind, debiting nothing, and reports a failure in
  `CatchUp`. With several routes a failure stops only its route, kept
  for the control path (`take_failures`), and a route without a TX half
  this call is out for the call. `RouteCounters` count skipped, late and
  uncancelled copies per route. `StageError::OutOfOrder` refuses a copy
  not above its route's last one.
- A publication over redundant paths (redundant-paths.md section 7, RP-10):
  `Outbound::new_routed` (crate-internal: test-only until the publication
  wiring) takes one endpoint and destination per path, and
  `Outbound::serve_routes` sends each committed datagram once on every
  path, debited once (`karyos_io::lanes::routes::RoutedLaneSender`). Repair
  stays on the founding path, on its queues. A route's failure resets only
  its endpoint (`Outbound::post_reset_requests`) and a faulted queue is
  retried on its route; a reliable lane reads again after a reset only when
  no route still holds its copies. A guard covers every path
  (`GuardGate::new_routed`, `GuardGate::stage_copy`,
  `GuardGate::reopen_route`): each copy's exposure loads the guard, a
  position is rate charged once, the applied positions are the highest
  submitted on any path, and the work in flight counts every path.
- A seal gate on the skip policy (conflated-network-images.md (b)):
  `SkipPolicy::duty_gated` and `SkipPolicy::range_unavailable_gated` ask a
  `SealGate` before each seal. While it answers `GateAnswer::Pending`, the
  hole stays due, `SkipReport::gated` counts it, and the hole is posted to
  the receive owner (`ReceiveOwner::post_seal`, `ReceiveOwner::posted`): a
  frame overlapping a posted interval is not committed and reads
  `Received::LateAfterSkip`, so the interval is sealed whole. `duty` and
  `range_unavailable` use `Ungated`, which always permits, and seal as
  before.
- `karyos_sys::freshness::BarrierMailbox` (`MAILBOX_WORDS`,
  `SealRequest`, `FreshnessError::UnknownRequest`): one lane image's seal
  mailbox between its receive owner and its conflated view's feeder,
  words `[request, start, end, ack, attached]` (conflated-network-images.md
  (b)). The owner posts the interval it intends to seal and seals after
  the acknowledgement; the feeder acknowledges only after its barrier
  published the loss. The Loom model `tests/loom_barrier_mailbox.rs`
  checks it with the barrier, a fresh slot and the terminal cell: four
  scenarios (acknowledgement, timeout, ring-full race, attach race) and
  seven negative controls.
- Receiver roles and tags reach the network agents, driver-internal (MC-1,
  MC-2; the public way in is owner item 7). A network publication can
  carry `PublicationRoles` (its strategy, required receiver ids and tagged
  ones), which build its membership, now created at the add's time so a
  required receiver's join is timed from it. A network subscription can
  carry a `ReceiverIdentity` (a configured `receiver_id` and its
  `group_tag`), which its images name in every RB block (SMs, NAKs, RTTM
  requests and reply matching) instead of the id derived from their slot.
  Subscriptions sharing a receiver entry must agree on its identity
  (`DriverError::ReceiverIdentityMismatch`, `ErrorCode` 15). An SM whose
  declared tag is not the one configured for its receiver is dropped whole
  before the sender's binding (`SenderCounters::sm_tag_mismatch`), so it
  never establishes a session or holds retention (MC-2).
- `make netem` (`scripts/netem-test.sh`, W6): the network fault tests in
  Linux Docker with `NET_ADMIN`, under tc netem on the container's own
  loopback (default profile: 2% loss, 10% reorder, 1 ms delay, 1%
  duplicate; `KARYOS_NETEM` sets another). The log names the kernel and
  the profile. Without the capability the run prints SKIPPED and fails,
  and it fails if no netem test ran; the tests refuse to run outside the
  job. A first test checks that the shaping takes effect. The first
  driver fault test, N1 (`net::e2e::netem`), checks over these faults that
  an unreliable channel delivers each message at most once and in order
  and reports every lost one as a local gap. N2 checks that a reliable
  channel delivers every message exactly once and in order through NAKs
  and the sender's repairs, and N3 does the same with 5% duplicates (the
  test raises netem's duplicate rate and restores the job's profile).
- `EmbeddedDriver::add_guarded_network_publication(config, channel,
  NetworkGuard { guard, messages, rate })`: a network publication whose
  lane streams are guarded before its sender exists, and whose sender
  gate is registered with the guard's owner, so it takes part in the
  close acknowledgement from its first send. It is deregistered when the
  sender refuses or returns the publication, or when the add fails. A
  guarded publication needs a spare slot for its walker beyond the
  sender's reservation (`GuardWalkerUnavailable` otherwise).
  `add_network_publication` is unchanged. Closing the network, or an agent
  failing, releases every tracked guard sender for deregistration, so no
  guard close waits on a sender that will never apply it;
  `NetworkShutdown::guard_senders_released` reports how many.
- The receiver's controls report a third send outcome. `ReportSlot` and
  `ReportGuard` (formerly `ProbeSlot` and `ProbeGuard`) carry an RTTM
  REQUEST's or a NAK's submission back to the receiver: submitted at the
  start read before the call, not submitted, or uncertain, when the
  backend left its exposure unknown (RC-6). `ControlSendError::Uncertain`
  reports it, and an uncertain RTT probe yields no sample.
- The sender agent can run a guard gate for a network publication (the
  embedded driver wires it in a later change). `AgentCommand::AddPublication`
  takes an optional `GuardSpec` (the guard word, the applied-epoch cell
  registered with the guard's owner, the open epoch and the rate policy),
  and the publication's `Outbound` then runs its `GuardGate`: the probe and
  the exposure both ask it, heads are staged and reopened through it, and
  the applied epoch reaches the close acknowledgement. A close is local on
  sockets (O-11, GC-6): nothing more leaves the sender, first sends and
  repairs alike (repairs load the word each cycle), and no abort is sent.
  An aborted lane's staged items are returned (`LaneSender::cancel`), so
  the close's work drains, and a close applies without a usable endpoint
  too.
- The sender agent repairs reliable publications (R4, R5, R7 wired).
  `agents::repair::RepairPath` admits a bound receiver's NAK against the
  lane's retention floor and submitted frontier, coalesces it into a
  group job, and serves jobs through the NAK read into one scratch
  datagram and a repair queue outside the lane sender, so repairs never
  touch the data DRR. The cycle runs control, repair and first sends in
  that order. Repairs take turns across publications within one
  `RepairConfig::budget` per cycle, and at most `naks_per_cycle` NAKs are
  admitted. Admission's and step 8's ERR NAK_REPLYs go to the receiver's
  bound source through the ERR linger. A repair read out of word 0 loads
  now suspends the call with the job and the lane's deficit kept
  (`RepairReadError::Budget`). `AgentConfig::repair` holds the settings.
  A step 8 ERR goes to the requester's binding as it is at the send; one
  past the cycle's reply list counts `SenderCounters::nak_replies_dropped`.
- The network agents measure RTT (RC-1). Each installed image sends one
  RTTM REQUEST per bound path and `rtt_probe_interval`; the sender reads
  the clock immediately before the submitting call and reports the start
  only when the backend submitted it (`ProbeSlot`, `ProbeGuard`). A REPLY
  gives a sample only from a bound path naming the image and this
  receiver, and a lost path's late report is ignored. The sender answers
  bound receivers within `rttm_reply_rate` per source, echoing the probe
  id with its service delay. `AgentConfig::rtt` holds the settings.
  `OsProbeIds` is no longer `Copy` or `Clone`, `ProbeIds::refill` and
  `RttProbes::refill_ids` return whether they drew, and
  `RttProbes::generation` and `PathBindings::key` are new. A REPLY that
  overtakes the sender's final report settles from the start it
  published while sending. The sender finds an SM's binding by its
  incarnation too, so an earlier incarnation's binding from the same
  receiver no longer shadows the current one (`sm_unbound`).
- The driver's sender and receiver agents run multicast flow control. Each
  publication's `Outbound` holds a `Membership` (interim defaults: no
  roles, `Strategy::Min`, a minimum window of one maximum frame, a maximum
  window of half a term); a lane stages a frame only when the whole frame
  fits below the receivers' edge (`window_waits`, once per wait), an
  unresolved required loss holds every lane, staged heads included
  (`held`), and a configured required receiver not yet joined holds new
  staging (`not_joined`). Once a required receiver joins, a lane's
  registered position follows the least position the required receivers
  consumed. The membership follows the driver's `sm_interval`,
  `image_liveness_timeout` and `idle_image_timeout`, checked at
  configuration, and starts each lane's sent frontier at the reader's
  join. Accepted SMs reach the membership, and a binding that expires, is
  evicted or moves to another receiver id is reported gone in the same
  call, a reset binding's former receiver included. The receiver sends each
  image's SMs on its `SmSchedule` (join, interval and quarter window
  progress), and records an SM as sent only once it is posted.
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
  `ProbeIds`, so an off-path spoofer cannot forge a reply; in the driver
  a pool, `OsProbeIds`, drawn from the operating system on the control
  path and restocked by `refill_ids` once at or below half full, so the
  duty path makes no system call and a refill each control cycle is free
  in steady state; an empty pool or failed draw is counted),
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
  15647). Only an establishment (`expect`) or a configured required
  receiver may take another receiver's tombstone slot, an `expect`
  refused for its limits keeps the tombstone, and an SM's credit faults
  are counted before the tombstone's (ACS 15663). `timers` expires members
  within a bound with a fair
  cursor, and membership events are queued in a bounded queue. Not wired
  yet: the sender agent's SM handoff and gate.
- Receiver SM schedule (P2.7, multicast-flow-control.md M3 and MC-6, ACS
  15689): `karyos_driver::sm_schedule::SmSchedule`, one per image. It
  makes the first SM due at once, then one every `sm_interval` (by
  `age_ns`), and one as soon as a lane's consumption advances by a quarter
  of its window. The SM reports, per lane, the larger of the given and the
  last reported consumption, so it is never stale at the sender; a lower
  value is counted as a regression. An SM is recorded only once sent, so
  an unsent one stays due. Not wired yet: the receiver agent's SM path.
- NAK admission at the sender (phase 6 R4, reliable-transport.md, ACS
  15597, 15701 and 15711): `karyos_driver::repair::admission::Admission`
  runs steps 1 to 5 of the eight-step order, the first failure deciding.
  Context and the requester window drop with no reply, each counted: an
  unreliable publication, an unknown requester or lane, a range below the
  join point (counted apart before any accepted SM), below the
  consumption (stale) or beyond `consumption + window`. A range leaving
  its term, or beyond the NAK bound, answers `RANGE_INVALID`; one below
  the floor answers `RANGE_UNAVAILABLE` with the floor, before the
  frontier check. At most one ERR goes per receiver, lane and range
  within `nak_reply_linger`, from a bounded table. A passing NAK is a
  `Request` for the job table (R5). `Membership::requester` gives what a
  NAK is checked against: a live member's join point, consumption and
  window, or an expected entry's answered join point before its first SM
  (`expect` now takes the answer's joins).
- Repair jobs and coalescing (phase 6 R5, reliable-transport.md, RC-11,
  ACS 15597 and 15701): `karyos_driver::repair::jobs::Jobs`, steps 6 and
  7 of NAK admission. The key is the lane, the exact range and the
  response domain (`Group`, or `Requester` with the receiver and its
  membership generation); an exact duplicate joins the pending job and
  adds its requester, and nothing wider merges. The linger
  (`repair_linger`, 1 ms) starts at the last frame's submission and drops
  duplicates without extending; a known failure or an uncertain
  submission starts none. `repair_jobs` (64) and `repair_linger_entries`
  (256) are bounded: a full table drops and counts. Jobs keep their
  unsent cursor and a checked slot generation; requester lists are
  allocated at construction.
- Repair scheduling (phase 6 R7, reliable-transport.md, RC-12 and RC-13,
  owner decision P3, ACS 15597 and 15701):
  `karyos_driver::repair::scheduler::Scheduler` serves the pending jobs
  with its own protocol `Drr` over the lanes, with the data path's quanta,
  within the repair budget (64 KiB, 4096 word 0 loads), so a budget too
  small for a head keeps the lane's deficit. Each lane serves its oldest
  job from its cursor, one whole frame at a time, read through
  `RepairRead` (a DATA frame charged its aligned length, PAD and ABORTED
  32 bytes) and submitted through `RepairSubmit`. At each head, step 8 and
  the end proof: `BadRequest` or an extent crossing the end answers
  `RANGE_INVALID`, `Unavailable` or `Revoked` answers `RANGE_UNAVAILABLE`
  with the floor read after, both to every requester; `CorruptTerm`,
  `Retry` and `TooSmall` drop the job with no ERR. A submitted last frame
  ends the job and starts its linger; an uncertain one ends it
  unresolved; no room stops the call as backpressure. A probe reads at
  most one head, so reads and ERRs stay within the loads budget; a known
  failed submission holds its lane for the rest of the call; a head the
  DRR would refuse is dropped and counted (ACS 15773). The round robin
  across incarnations is the wiring's. Not wired yet, and the NAK read
  origin in karyos-sys comes separately.
- Repair simulator scenarios (phase 6, ACS 15767): karyos-sim's
  `tests/repair.rs` runs NAK admission, the job table and the repair
  scheduler together on virtual time against a scripted two-lane log and
  backend, 40 seeds each. `repair-mixed` has receivers NAKing identical,
  overlapping and malformed ranges with duplicates and reorder, a floor
  that moves, random budgets and every submission outcome; it checks that
  every job ends exactly once and is never served after, that no
  duplicate within `repair_linger` creates a job, that no ERR repeats
  within `nak_reply_linger` (step 8 ERRs included), and that
  `RANGE_UNAVAILABLE` names the floor of that moment. `repair-fair` checks
  that two backlogged lanes stay within `Q + 2 F` of each other. Each
  oracle fails under a mutant of the components.
- NAK reads in the sender read capability (phase 6, network-sessions-sender.md
  S2 2.3, ACS 15762 and 15763): `SenderRead::read_nak(from, NakRead {
  bound, loads }, out)` copies whole frames from an untrusted NAK position
  below the NAK bound, never moving the cursor, the open block, the
  registered position or the boundary ring, and never feeding C-9. The
  position is proved a frame boundary by a word 0 walk from a checkpoint
  (`nak_checkpoint_stride`, default 64 KiB, `SenderRead::with_nak_stride`):
  every frame the cursor path copies records, per stride it passes, the
  first frame start at or after the stride with its block's end, in arrays
  tagged with their term count, cleared on a new count and read only for
  it. The walk goes frame by frame, charging each load before it is made,
  and takes the end of a block it enters from the cursor's open block, the
  next stride's entry or its END: from the entry of its own stride a scan
  spends at most `stride / 32 + 1` loads and returns the loads spent; it
  never reads a payload word. A NAK at an uncommitted block is
  `BadRequest`. New
  `ReadError::BadRequest` and `ReadError::Budget`, and NAK counters.
- Membership simulator scenarios (P2.7 C preparation, ACS 15661):
  karyos-sim's `tests/membership.rs` drives `Membership` on virtual time,
  40 seeds each. `membership-required-loss` stops admission exactly
  `receiver_timeout` after a dead required receiver's last SM, holds every
  lane and keeps its consumption in retention. `membership-optional-pause`
  checks that a paused optional receiver past `pause_timeout` does not
  rejoin on stationary SMs, that the sender moves past its edge, and that
  it rejoins once it advances. `membership-two-paths` checks that SM
  copies over a second path, and that path's bindings coming and going,
  match a one-path shadow table at every step. On every step the sent
  position stays within each required member's edge.

### Fixed

- The network keeps one time base in every threading mode. In
  `ThreadingMode::Shared` the agents' cycles took the driver's injectable
  clock while their role clocks read `host_monotonic_ns`. On Linux every
  RTTM reply was then late (no RTT sample) and a receiver never asked
  again for a hole whose NAK or repair was lost. The network now reads
  `host_monotonic_ns` for its cycles and its close, as runner threads do;
  the driver's clock times claim deadlines only.

## [0.1.0-alpha.1]: 2026-10-15

First alpha: the embedded driver on every supported platform and the
cross-process control path on Linux. See
[RELEASE-NOTES-0.1.0-alpha.1.md](RELEASE-NOTES-0.1.0-alpha.1.md).
- `SenderRead::floor`: the retention floor its reads enforce (Acquire),
  for NAK admission to check requests against before the read.

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
