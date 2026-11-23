<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to Karyos are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0 any
release may break APIs, wire formats and shared-memory layouts.

## [Unreleased]

## [0.1.0-alpha.4]: 2026-11-23

### Added

- `SnapshotConfig::large` (byte trigger `LARGE_EVERY_BYTES`, 1 GiB) to pair with `DedupConfig::large`, and `SnapshotConfig::check_sessions`, which refuses a byte trigger below the session table's reserved bytes so the large profile cannot run with the 256 MiB default trigger unnoticed (karyos#1002).

- Live replay delivers a checkpoint a writer recorded for an event a follower had already given, without the prefix advancing: `Recovery::checkpoints` lets a poll discover it, and `ReplayCursor::follow` then gives it as `Step::LateCheckpoint`, before any later event (karyos#1003).

- With `AgentConfig::copy_location`, the running Archive records each recording that closes sealed as a verified local copy in the copy catalog. Each segment file is made immutable through the platform backend (the immutable attribute on Linux), and the copy records the enforcement that applies, the digest of its seals, and this Archive's location. `SegmentStore::segment_files` lists a recording's segment files (karyos#1024).

- The codec derive takes one lifetime, variable fields (`#[field(var, min, max)]`, `&str` or `&[u8]`), fields of any type through a `with` module (`#[field(offset, width, with)]`) and a message check (`#[message(check)]`). `ControlResponse` is derived with them, byte for byte as before (karyos#1029).

- The simulation harness can inject faults into a server's driver (`DriveFault`), its service's answers and a client's reads (`Case::faults`, tests only), and the raft-rs candidate now backs `AppliedNotDurable`, `ReleasedBeforePersisted`, `DivergentResponse` and `NotLinearizable` with a real core (karyos#1038).

- `ServiceContainer::propose` enforces ADR-0087's registration gate for every host: a leader whose log has not applied the session bounds proposes no `Register` and gets `ProposeRefused::BoundsPending` (retryable; the host holds or refuses it), so no registration precedes the first `SessionBounds` entry. `Propose` gains a provided `leads` method, `true` by default, so a follower's registration still reaches its core and is refused with the leader's hint. The simulator's delivery harness now goes through this gate instead of its own check (karyos#1053).

- A channel URI key `path-skew=<duration>` (0 to 1 s, owner item 17), consumed by both sides of the channel: the sender absorbs NAK copies on other paths within it and the receiver's images wait it before NAKing or sealing a gap, in place of the driver's `path_policy.skew_window` and `path_skew_window` (default 1 ms, unchanged). Validated once at channel admission; every handle of one subscription key must ask for the same value; a conflated view of an unreliable channel checks its far-window bound with the channel's value. `UdpConfig` gains `path_skew` (karyos#1056).

- `karyos_trace::clocks::record::ClockRecord` reads a calibration journal of both record types of ADR-0090, a calibration (type 1) and a UTC reference record (type 2), each as its own, and skips a type it does not know (karyos#1065).

- Time evidence entries of ADR-0095: `karyos_archive::integrity::time_evidence`, with each typed refusal, an `EntryStore` that appends and seals entries in `time-evidence/` (its own integrity journal), and an entry's verdict against a requirement. `karyos-catalog verify --time-requirement NS:GRAN` reports the time verdict per entry and combined, apart from integrity. It reports `met` only for entries the entries' journal verifies under the trust and the anchors (`--time-anchors` names that journal's anchor stores) (karyos#1065).

- A byte budget for the session table: `SessionTable::new_within` and `ContainerConfig::session_budget` (default `dedup::DEFAULT_BUDGET`, 2 GiB, room for the large profile) refuse bounds whose reserved bytes pass it with `ConfigError::OverBudget`, for the container's own bounds and for bounds a log entry carries, before anything is reserved. No bounds can drive a replica, or a test host, into memory exhaustion on any operating system (karyos#1070).

- `karyos_archive::replication::transport`: the two ends of a replication. `Sender` sends a request's stored bytes in chunks then each range's seal, in order, with the status the design names: caught up, ended, interrupted by a purge or a gap, stopped. It refuses an unknown recording with code 2 and a request off a seal boundary with code 4. `Receiver` stores what arrives and counts a range only once its seal verifies on the replica's own bytes (karyos#1072). A poll sends at most its byte budget, and an interrupted status names the store's start after a purge (ADR-0094; vector P-7).

- `karyos-catalog verify` reports each copy the copy catalog commits, with its location, state and enforcement (immutable attribute, object lock or none), in text and JSON (`copies::replay_current` reads them without opening the catalog for writing), replayed from the journal snapshot it verified up to its first inconsistent record, and the immutable attribute each copy in the directory actually carries, read from its segment files on Linux and macOS; a recorded attribute the files do not carry, or a copy change the copy catalog does not hold, is reported inconsistent (exit 1). The running Archive's retention releases each removed segment's immutable attribute before a purge deletes it (karyos#1087).

- With sealing on, the running Archive seals each recording group's journal in an integrity journal in the group journal directory, at most 1 MiB per seal, so `karyos-catalog verify <groups dir>` reports the group journals' ranges with their outcomes (karyos#1088).

- `karyosd --archive` takes a retention policy (`--archive-retain-for`, `--archive-purge manual|after-expiry`, `--archive-min-copies`) with the copy catalog's `--archive-copy-location`, and the Archive then serves `PurgeRecording` through its retention engine against the recording's store: refused `legal_hold`, `not_expired`, `below_min_copies`, `no_close_time` and the rest by name, or purged (karyos#1093).
- The catalog's `Stopped` record carries the recording's UTC close time (ADR-0093), never below an earlier stop's, chained in the integrity journal. A purge counts the retention from it, raised but never lowered by the segments' modification times, and refuses `no_close_time` without one. A catalog with such a record cannot be opened by an earlier build (karyos#1093).
- A purge validates against a read-only view of the stopped store, so segments a local copy made immutable still reach the engine and a refused purge changes no file; a cutoff past the written end is refused `not_a_write_start` before any file is listed; and the Archive completes or cancels the purge intents a crash left outstanding at start, before it serves any request (karyos#1093).

- Concurrent guarded publication handles in process, part (c) of karyos#1102 (ADR-0092).
  - **`EmbeddedDriver::concurrent_publication` on a guarded stream.** It now issues a guarded handle bound to the next slot of the incarnation's shared outcome ring. A refused slot frees the handle's publisher slot. It no longer refuses with `GC-7`. After a guard close and reopen, the first call creates the stream's next incarnation, as `publication` does.
  - **`GuardBinding::new_shared`.** It binds a handle to its slot of a layout version 3 ring. Its quota `C_m` is read from the ring.
  - **`ClientConcurrentPublication::with_guard`, `guard` and `poll_outcomes`.** A guarded concurrent handle records the `(lane, start)` of each block it reserves. It answers `BackPressured` at its own quota and delivers only its own message records.
  - **`Gated` and `RateLimited`.** These are new `ConcurrentOfferOutcome` and `ConcurrentClaimOutcome` variants (pre-1.0 additions). A guarded handle reports a gate seal as `Gated`; an unguarded one still reports `Closed`.
  - **Detach.** The walker detaches a dropped in-process handle's slot, so it no longer holds the ring's room back.
  - **`SharedOutcomeWriter::revoke`.** It takes back a slot attached for a handle that was never issued, so a failed issuance consumes no slot of the incarnation. A guarded concurrent handle keeps reporting `Gated` on every call after a gate seal, and a reservation its set cannot keep ends its outcome stream (`OutcomesLost`) instead of asserting. The simulator retries a concurrent `RateLimited` outcome.

- Guard support in the concurrent log buffer, part (a) of karyos#1102 (ADR-0092).
  - **`Gated` variants.** A concurrent handle that meets a gate seal (guard close, missed deadline or schedule violation) now reports `ConcurrentOfferOutcome::Gated` or `ConcurrentClaimOutcome::Gated`, as an exclusive one reports `Gated`, instead of `Closed`. Both variants are pre-1.0 additions.
  - **`Conductor::abort_marked_claims`.** It aborts a concurrent buffer's outstanding claims at once, whatever their deadlines, for a guard close.
  - **Unchanged for now.** The client's concurrent handle still reports a gate seal as `Closed` until the concurrent guarded handle lands (karyos#1102 part c).

- Driver support for concurrent guarded streams, part (b) of karyos#1102 (ADR-0092).
  - **Guarding a concurrent stream.** `EmbeddedDriver::guard_stream` now accepts a concurrent stream with up to 64 publisher slots. Its slot count is `H`, and `H` handles of `C_m` reserved messages each must fit half a term. More than 64 slots, or a window that does not fit, is `InvalidConfig`.
  - **One shared outcome ring per incarnation.** The first guarded handle creates a layout version 3 ring, bound to the guard's open epoch and to that handle's client. A handle of another client is refused with `Sys(InvalidPublicationMode { reason: "GC-7-client" })`. One beyond `H` is refused with the new `DriverError::GuardHandleSlotsExhausted`. A slot is never issued twice in one incarnation, and a detached handle leaves the room minimum.
  - **The walker.** It writes every record of a concurrent guarded stream through `SharedOutcomeWriter`, against one consumed cell per slot. A guard close repeats `abort_marked_claims` while it reports waiting. A lapped walker faults every live handle with the new `SharedOutcomeWriter::abandon`.
  - **Unchanged for now.** `concurrent_publication` refuses a guarded stream with `Sys(InvalidPublicationMode { reason: "GC-7" })` until the client handle binds a slot (karyos#1102 part c).

- Remote concurrent guarded publication handles, part (d) of karyos#1102 (ADR-0092).
  - **Grant.** A remote client's `AddConcurrentPublication` on a guarded stream is granted with the incarnation's shared outcome ring, the handle's own consumed cell and the guard words beside its log buffer. The first handle creates the ring in a driver-only region. The consumed cell record carries the handle's slot of the ring as the new admission capability `GuardSlot { slot }` (code 6), which only that record of a guarded concurrent grant may carry.
  - **`RemoteClient::take_concurrent_publication`.** It binds a guarded grant to its slot with `GuardBinding::new_shared`, so the handle answers `BackPressured` at its quota and reads only its own message records.
  - **Refusals.** A handle beyond the stream's `H` is refused with the new `ErrorCode::GuardHandlesExhausted` (code 28), whose detail is `H`; another client's handle on the same incarnation with `InvalidPublicationMode` (`GC-7-client`). A refused slot ends the handle's publisher registration.
  - **Detach.** When a remote handle's consumed cell grant ends, its slot leaves the ring's room minimum.
  - **In-process command ring.** A client of the in-process command ring is refused a guarded stream's concurrent handle (`InvalidPublicationMode`), as it already was the exclusive one: it has no grant to carry the handle's slot.

- The Archive's control server answers a replica's `ReplicateRecording` and `StopReplication` (schema 6, ADR-0091; karyos#1113). The agent streams the recording's sealed ranges, each range's bytes before its seal, at most the replay budget per cycle, with a status at least once a second; an unknown recording is refused with code 2 and a request off a seal boundary with code 4. A recording that stops while it replicates is reopened read only and the replication goes on to its end.

- `karyosd --replicate <rec>,<host:port>,<stream>,<req>,<resp>[,on-demand]` pushes a recording to a replica (ADR-0102; karyos#1113). Each replication has its own control pair served against the Archive, so a stalled replica never holds back the shared pair. The daemon's own requester asks from the recording's current start. The answers are forwarded byte for byte on a reliable UDP publication, on a fresh incarnation per request. While the publication refuses a message, that message is held and nothing more is read. Output of an older request is discarded unread. A stop forwards nothing more at once and waits for the agent to report the request gone (`ArchiveHandle::post_replication_active`) before a replacement starts. An `interrupted` status, a refusal, or a connection to the replica that came back and stayed up 1 s asks again after a backoff of 1 s doubling to 60 s; an interior gap ends the replication with a warning. Replication fails closed: it needs `--replication-trusted-network`. A stop now drops the replication's pending output in the agent.

- The integrity journal gains seal kinds 9 (offload) and 10 (restore) for tiering by whole segments (ADR-0104). `karyos-archive` splits `Tiering::offload` into `upload_segment`, which puts and reads back a segment's range objects and its original index with no custody change, and `commit_segment`, which rechecks `min_copies` without the local copy, chains the copy records and the offload record, raises the start durably, then releases and removes the segment's files; `reconcile` and `reconcile_floors` finish an offload a crash cut short. The floor record keeps the offload floor, and `verify` reports each range's residency (`local` or `offloaded`, "bytes remote, not rechecked locally") apart from its five outcomes, so an offloaded range is never `inconsistent` for a shortened index. A journal holding kind 9 or 10, or a floor record with an offload floor, cannot be opened by an earlier build (karyos#1113).
- A purge of a recording with offloaded segments is refused `offloaded` at any cutoff, and purge recovery and purge evidence start from the recording's lowest retained position, never the local start (karyos#1113).

- A test that the Archive agent's start completes a purge intent a crash left before its deletion when the intent still passes its recheck (authorised, expired, copied elsewhere): the floor moves, one integrity purge record is written and the id is free again (karyos#1122). The start's reconciliation itself came with karyos#1121.

- The Archive agent chains its configured retention policy (`karyosd --archive-retain-for`, `--archive-purge`, `--archive-min-copies`) in the integrity journal at start through the policy book, so the policy in force for a purged range can be shown from the chain (SPEC.md 8.4; karyos#1123). A start with changed terms records the next version, an unchanged one records nothing, and purges are checked against the recorded version. `PolicyBook::current` and `PolicyBook::record_configured` are new.

- The running Archive takes time evidence entries (`ArchiveHandle::record_time_evidence`) once their range is sealed, when the host made `time-evidence/`: each is durable and sealed there on return. An entry is refused unless its whole range lies within its recording's sealed range; a recording with no seal is refused, never read as sealed to zero. Its head signer, shared, signs and anchors the entries' journal on the Archive's schedule and trust root, as a journal of its own: `ArchiveSigning::time_evidence_journal_id`, the trust file's `time-journal N`, which must differ from the journal's; it is never guessed: without that line time evidence is refused (`AgentError::NoTimeEvidenceJournal`, and `karyos-catalog verify --time-requirement` fails with "no time-journal line"). The signer completes one journal's head before it is asked for the other's, and a signing poll on a poisoned signer lock is refused and counted (`ArchiveHandle::poisoned_signer`) (ADR-0095; karyos#1128). `karyos-catalog verify --time-requirement` now needs `--time-anchors`: the entries' journal has its own anchor store, and `--anchors` no longer stands in for it; it verifies that journal as `time-journal`, so an anchor of the integrity journal is `WrongJournal` there.

- A group store's time evidence is signed and verified (ADR-0098 item 2; karyos#1137). A signing Archive signs and anchors each group directory's store journal with its own signer, under `GroupTimeEvidence::with_journal_id`, which a signing Archive requires (`NoTimeEvidenceJournal`), which may not be one of the Archive's own journals (`SharedJournalId`), and which every group of one directory shares (`GroupStoreJournalId`); the declaration is checked before any file is made. `karyos-catalog verify --time-requirement` checks every entry against what its directory's chain seals: an entry naming positions the chain does not seal, overlapping another of its subject, or of the zero clock identity other than the sentinel is an integrity failure (exit 2); a sealed range of a subject with entries that none covers is reported `uncovered no_evidence` (JSON `gaps`); an entry of the zero identity is always `no_evidence`. `karyosd --archive-time-evidence` makes `<archive>/time-evidence/` before the agent starts.

- A recording group's time evidence in the running Archive (ADR-0098; karyos#1137). `StartGroup::with_time_evidence` declares the capture session's event clock and its `calibration_wait`; `ArchiveHandle::set_calibration_source` gives the agent its calibration snapshots (`time_producer::CalibrationSource`). When the Archive seals and the host made `time-evidence/` in the group journal directory, each sealed range of the group's journal gets its entries there, produced by `time_producer::produce` from the range's events: records before the session's start, and timers this session did not schedule, are "provenance unknown". A range waits for the calibrations to reach its largest timestamp at most `calibration_wait`. Declaring the all zero clock identity is refused (`AgentError::ZeroEventClock`), and `EntryStore::append` refuses a zero identity entry other than the sentinel (`StoreError::Sentinel`).

- `integrity::time_producer` (ADR-0098; karyos#1137): the producer of a recording group's time evidence entries. `produce` partitions a sealed range's events, in position order, into runs of uniform provenance before it computes each run's extrema and bounds, so each entry cites one calibration and one UTC reference record. Coverage comes from one `Snapshot` of the calibration journal and needs the producer's completeness boundary (later records of both kinds past the range), no reported loss, a unique calibration and a unique UTC reference; otherwise the bounds are `no_evidence`. Positions with no declared `EventClock`, or timers scheduled in an earlier capture session, get an all zero identity.

- A test for a privileged Linux runner (karyos#1143): with `CAP_LINUX_IMMUTABLE`, a running Archive's sealed segments cannot be opened for writing or removed, the store still reads them, and a purge releases each segment it removes before deleting it. It is ignored by default and fails, rather than skips, without the capability; `scripts/linux-test.sh` passes capabilities to its container through `KARYOS_LINUX_CAPS` (run: `KARYOS_LINUX_CAPS=LINUX_IMMUTABLE scripts/linux-test.sh -p karyos-archive --lib -- --ignored immutable_segments`).

- `karyos-trace --trace-span <ns>` declares the attribution span `D` (karyos#150). A journal loss then marks only the traces whose window it can meet, instead of every trace of the journal, and the report labels its count "complete under the declared span". Without the option `D` stays unbounded and the report is as before. The attributor also narrows a tail loss, or a loss before the first record, to the times of the journal's held drop ranges when they cover every lost sequence in one clock and epoch. Below `lost_before`, or over the tool's own mirror loss, it still marks every trace (quantstratum-docs: karyos/design/trace-attribution.md, "Narrowing with a declared span and drop ranges").

- The shared outcome ring of ADR-0092 in `karyos-sys` (part of karyos#177): `outcome_ring::shared`. It covers the layout version 3 header (`H` handle slots in word 14, `H * C_m + C_r + H` records), the driver's `SharedOutcomeWriter` and each handle's `SharedOutcomeReader`. The writer checks room against the minimum consumed count of the live handles. It faults every handle at that minimum, ties included and in slot order, with an `OutcomesLost` record naming its slot, then retries. The reader delivers a handle's own message records by the `(lane, start)` pairs it reserved, within its quota `C_m`, plus every range-side record. ADR-0092's vectors O-1 to O-4 are tests. The driver, client and C ABI do not use it yet, and concurrent guarded publications are still refused (GC-7).

- `karyos-sbe`, the home of the SBE 1.0 integration (SPEC §10.1; ADR-0052; karyos#631): an empty crate for now, forbidding `unsafe`, internal and unstable in alpha, depending on `karyos-feed` and never the reverse. `make sbe-graph-check`, in `make pre-push`, keeps the IronSBE admission record's boundary as an allowlist: only `ironsbe-core`, `ironsbe-schema` and `ironsbe-codegen` (a build dependency only) may be in the graph, only `karyos-sbe` may depend on them, and `karyos-feed` never depends on `karyos-sbe`, with negative controls for each. No IronSBE crate is added yet: the first one enters with the framing (karyos#646).

- A bench test that no wire authentication candidate of ADR-0086 is a runnable profile before its E1 or E2 selection (karyos#632).

- The channel URI grammar of paired unicast paths, `paths=<interface>@<endpoint>;...` (1 to 4, owner item 11), recorded in `CHANNEL-URI.md` section 6 and parsed into the new `Destination::PairedPaths`, with typed refusals for a repeated interface or endpoint, two address families, a mixture of paired and unpaired elements, too many paths, and any other destination key. `paths` with `destinations` is now a URI `Conflict` in either order. Drivers still refuse paired paths with `UnsupportedChannel` until unicast paths pass on real sockets (karyos#624; part of karyos#635).

- Dynamic multi-destination registration is public (karyos#644, ADR-0082): `EmbeddedDriver::add_dynamic_network_publication` publishes on a `control-mode=dynamic` channel with an explicit allowlist and optional roles, and `EmbeddedDriver::add_dynamic_network_subscription` registers a subscription with its receiver identity. Every other publication and subscription call, and a client's URI, still refuses dynamic mode, since none carries an allowlist or an identity. The refusal of karyos#944 is lifted on top of the fixes of karyos#940, #941 and #977.

- The SPEC §13 "Multi-destination isolation" contract test under `tagged` (karyos#645): `test_multi_destination_isolation_tagged_stopped_optional_is_removed`, and the full-table ERR case now checks by count that the table is left unchanged. With the existing `min`, `max`, required, retransmission and full-table tests every clause of the row is pinned except the authenticated registration one, which belongs to the authenticated capability (ADR-0076).

- `karyos_protocol::protection::HmacSha256`, the wire authentication profile that owner decision D51 selected: HMAC-SHA-256 with a 16-byte tag over the 32-byte envelope header of ADR-0086 section 2 and the inner frames. It checks every field against the channel binding before the tag, and compares the tag in constant time. It reproduces the independent envelope vectors byte for byte. `protection::replay::ReplayWindow` adds the 1024-sequence replay window of manifest 4.3, which advances only after a tag verifies. No channel uses either yet: `authenticated` stays refused at parse (part of karyos#648).
- Alongside it, `protection::Verdict::Accept` now carries the offset of the frames (`start`) as well as their length, so that an envelope can lead the frames. `protection::Rejection` gains one reason per envelope check.

- The `require-abort-ack` channel URI key, refused as `SecurityUnsupported` for `authenticated` while that capability is unsupported (owner decision item 8; karyos#648).

- A channel URI key `linger=<duration>` (0 to 60 s, the duration grammar) sets how long a removed publication keeps serving repair and repeating its EOS, overriding the driver's `publication_linger` (default 5 s, unchanged) for that publication; validated once at channel admission. `UdpConfig` gains a public `linger` field, so a struct literal of `UdpConfig` outside this workspace must name it. `path-skew` stays an unknown parameter until sender and receiver both consume it (karyos#652).

- A channel URI key `nak-control=<group:port>[;...]`, one multicast NAK control group per path, maps through the driver's one control group table (`NetworkConfig::nak_control_groups` seeds it, unchanged): a conflicting mapping is `DriverError::ControlGroupConflict`, a ninth entry `DriverError::ControlGroupsFull`, and an ambiguous path mapping is refused at parse time. `UdpConfig` gains `nak_control`. No group discovery is added (karyos#654).

- A unicast subscription accepts `endpoint=<host>:0`: the driver binds an ephemeral port before the subscription is ready and reports it in `NetworkSubscriptionReady` and on `Subscription::bound_address()`; a reset keeps that port. A publication refuses an `endpoint` on port 0 (`InvalidChannel`, new `ChannelConfig::check_publication`), groups, destinations and `control` keep refusing port 0, and port 0 with `paths` is a `Conflict` (karyos#656).

- `karyos-codec-derive`: `#[derive(Message)]` writes the `decode` and `encode` of a codec message of fixed fields, each at its offset with an optional check. `StopRecording`, `ListRecordings` and `StopReplay` use it, byte for byte as before. `make codec-derive-check` (in pre-push) shows `syn`, `quote` and `proc-macro2` in no runtime graph and that the derive adds no `syn` major (karyos#661).

- Sealing and the tamper-evidence hash chain of the Archive (SPEC.md §8.4, "Sealing and tamper evidence"; karyos#662): `karyos_archive::integrity` adds the versioned SHA-256 seal record, the append-only integrity journal with a monotonic counter and a link to the previous record, chained catalog changes, policy versions, key registry appends and purges, Cluster log seals bounded by the commit index, the `seal_interval` schedule for open segments, and the observable sealing backlog. A removed, reordered, renumbered or rewritten record and an altered sealed byte are each reported as a named inconsistency, and a crash while sealing leaves a chain recovery continues. CRC-32C stays as corruption detection.

- The trust bootstrap, the key registry and signed chain heads of the Archive (SPEC.md §8.4, "Trust bootstrap", "Signed heads and custody" and "Key registry"; karyos#663): `karyos_archive::integrity::trust` adds canonical versioned Ed25519 head bytes under an archival domain tag, a key registry whose entries the external authority endorses and whose digests are chained in the integrity journal, registration before first use, a registry rebuilt on reopen only from the entries the journal chains, with the registration timing checked on replay as on append nothing read or cut through a poisoned journal, an append accepted only from a registry whose whole history is the one the journal chains, each journal and ledger file created exclusively and held by one writer through an exclusive OS lock taken before anything is read or cut, a file made durable, name included, by whichever opener takes its lock, a registry recovered and appended only with the designated ledger file (`keys.kyk`) of its journal's own archive directory, with writes and recovery cuts refused through a stale handle or journal view, retirement, evidence-backed revocation under which a revoked key's head counts only with a caller-supplied anchor proved to predate the revocation (producing that proof is #664), and honest custody labels; `karyos_archive::integrity::signing` adds a coalesce-or-refuse signing backlog that never blocks sealing and counts a head as signed only once it belongs to the journal's chain, verifies under the registry and is stored durably, withdraws coverage a change of the registry's contents invalidates and, after a restart, only if the stored head verifies against the registry and the chain, keeping records left uncovered overdue, the coverage lag and an `anchor_interval` alarm on the oldest uncovered record, with an unconfigured interval refused.

- External anchors of the Archive's integrity chain and the copy catalog's immutability record (SPEC.md §8.4, "External anchors" and "Immutability enforcement"; karyos#664): `karyos_archive::integrity::anchor` adds versioned anchors of the replica journal, Cluster log, operator export and object-lock kinds with an off-host counter and receipt, refuses a local replica, a circular pair and the deferred RFC 3161 kind as external, detects a journal truncated below an anchored head (one shortened to exactly that head's position is not detectable from that anchor) and a chain that breaks below an anchor, rollback below an anchor, equivocation and store counter rollback per store kind and location, accepts a revoked key's head only with evidence that it was anchored before the revocation, reports an old anchor as covering its prefix only and a missing anchor as a stated absence, checks ancestry and an anchor policy, and publishes anchors on a schedule to an operator export store that confirms only operator exports, which a verifier can read with read access only; `karyos_archive::integrity::copies` records each copy's state and immutability enforcement, chained as copy changes, recorded only through the journal handle the catalog was replayed from and only while it holds every committed change, with live counts and current state withheld after an ambiguous journal append, and replayed in journal order on reopen from an unpoisoned journal, and states when the storage cannot enforce it.

- `karyos-catalog verify` and the Archive's integrity verifier (SPEC.md §8.4, "Verification"; karyos#665): `karyos_archive::integrity::verify` recomputes each sealed range's digest, walks the chain, checks the key registry and signed heads under a trust root supplied outside the export, compares the chain with its anchors, and reports every range as `verified`, `beyond_anchor`, `unsealed`, `purged` or `inconsistent` with explicit reasons, the first inconsistent record and the signature and anchor coverage with the custody of the signed coverage (a test signer's heads are reported as no custody separation); evidence faults that hold for the whole chain, an anchor that fails validation among them, are reported, fail the command and raise a scrub event even when no sealed range exposes them. Missing trust is `inconsistent` with reason `untrusted_evidence`, apart from proved corruption; an index shortened below a seal is `inconsistent`; only `verified` carries a tamper-evidence statement; `purged` states that it proves nothing about payload bytes; every other outcome is C-EXTRACT's "unverifiable"; time evidence is reported in a separate field. A journal record that does not chain or decode is reported, and nothing from it on is verified, even when no range reaches it; a registry entry the journal commits but the export lacks makes the registry evidence malformed; a revoked key's head counts only with store evidence that it was anchored before the revocation; the registry is replayed with the same sequence, commitment and timing checks as on reopen over the accepted chain prefix only; an anchor counts only from an operator export store whose location the operator states (`--anchors HEX=DIR`), and a malformed anchor entry is malformed evidence; a seal larger than its recording is `inconsistent` without being read; a directory that does not exist, a store that cannot be opened or read or whose geometry cannot be recovered, an anchor store named on the command line but missing, and a report that cannot be written are errors; a chain-wide evidence fault qualifies a purged range like any other, and a revoked key's anchors and heads count on the same key-specific proof of ordering. A configurable scrub reverifies on a schedule and raises an event per mismatch and per journal fault. `make test-hooks-absent-check` also proves that no shipped build enables `karyos-archive`'s `test-hooks` feature, the archival test signer the `ed25519-dalek` admission allows only in tests (karyos#973).

- The A10 time evidence rules (SPEC.md §8.4, "Time evidence"; part of karyos#666): `karyos_archive::integrity::time` has the `source` and `sync_state` codes, unknown codes refused. The combined bound is computed in checked nanoseconds at an entry's minimum and maximum timestamps, inside the UTC reference's validity, and is never chained. A derived timestamp such as a clamped `event_time` gets its own bound and never the raw clock's. Entries split at every parameter change, non-monotone sample and leap boundary. The verdict follows SPEC.md's precedence, with the C-COMP reduction (`not_met` over `no_evidence` over `met`, gaps kept), and no verdict is made without the operator's requirement. `karyos-trace`'s `Calibration::convert` and `Calibration::covers` are now public.

- Retention policy, legal hold and the crash-safe purge of the Archive (SPEC.md §8.4, "Retention policy" and "Purge and legal hold"; R-CORE-22; karyos#667): `karyos_archive::integrity::retention` adds versioned retention policies and their bindings to a recording or a channel and stream class, kept in `policies.kyl` and chained in the integrity journal so a restart restores the effective policy and refuses to open when a committed version or binding is missing, with no built-in regulatory period; holds that apply without waiting on the operations journal, are reported applied only with evidence, survive restart while pending, and whose release fails closed, across a restart too, a release whose resolving marker is not yet written staying pending until a retry completes it, a hold neither journal could record being reported in memory only, and hold state made readable again only by replaying the restored journal; purges gated on authorisation, holds first, expiry and `min_copies` of verified copies elsewhere, a request for another recording than the store, an outstanding id reused, a cutoff that does not start a write the store can purge to (`SegmentStore::is_write_start`, `SegmentStore::can_purge_to`), lies past the sealed end or falls inside a sealed range, and a scheduled purge under a manual policy refused, recovery rechecking the same boundaries before the floor moves, every refusal journalled with its reason; and a purge over `SegmentStore::purge_before` that journals its intent first, records the purged range, from the start its intent recorded, with its seal digest in the integrity journal, and is rechecked on recovery so a hold or policy change after a crash stops the deletion. `--archive-min-free` is unchanged.

- `integrity::export::assemble`, the exporter's layout of an Archive export (ADR-0103; karyos#668): the journals with their seal records, signed heads, anchors and registry entries, then the manifest, frames, codec schemas, clock records, time evidence, policies and bindings, in the design's order and with its pinned readings (empty sections omitted, one frames chunk per recording, an empty time evidence store carried when asked). Built from the Archive's own record types, it reproduces the blind golden vectors X-5 to X-12 byte for byte.

- `integrity::export`, the Archive export file container of ADR-0103 (karyos#668): its 64 byte header, typed sections (kinds 1 to 12) and SHA-256 trailer, encoded and decoded with the design's typed refusals in order (`Trailer`, `Magic`, `Version`, `Reserved`, `Kind`, `SectionVersion`, `Length`, `Order`, `Count`). The golden vectors X-1 to X-4 encode and decode exactly, and X-5 to X-12, derived blind in quantstratum-docs#979, decode and re-encode byte for byte. The exporter and the offline verifier follow.

- `integrity::export::offline::verify_export` verifies an Archive export offline (ADR-0103 design section 5; karyos#668), with the external trust only:
  - **Integrity:** each carried journal is verified by the online verifier over the export's own records, so the outcomes are the online ones.
  - **Completeness:** registry, policy and binding rows and the time evidence entries are checked reciprocally against their seals; an omission is `OfflineError::Incomplete`.
  - **Anchored run:** only records up to the latest trusted anchored head grant trust, while retirements and revocations always count.
  - **Policies:** a policy is proven only through a recording binding; a class binding is reported unproven.
  - **Time:** a recording's time verdict is `met` only with full anchored coverage.
  
  The blind vectors X-5 to X-12 reach their expected verdicts.

- Replica verification and tiered storage logic of the Archive (SPEC.md §8.4, "Replication" and "Tiered storage"; part of karyos#669): `karyos_archive::integrity::replication` records what arrives before its seal as unverified, counts a range as a copy only after it verified against the source seal, and reports the replication lag; `karyos_archive::integrity::tiering` offloads a sealed range behind an `ObjectStore` trait on the control path, checking `min_copies` before it acts, refusing a corrupt local range, recording the remote copy only after it read back verified and removing the local range only then, and restores an offloaded range for replay only once it verifies.

- The Retention integrity contract tests (SPEC.md:946; part of karyos#670): `karyos_archive::integrity::contract_tests` has one `test_retention_integrity_<scenario>_<expected>` test for each of the row's cases except the offline export (karyos#668). The cases are sealing alteration, removal and crash, the signer outage, revocation and pre-revocation anchoring, anchor truncation, rollback, trust, conflict and equivocation, the shortened index, each integrity outcome, the time evidence cases with the verdict precedence, and purge and hold under crash and at restart. Integrity outcomes and time verdicts are asserted apart.

- The C5 harness's `ConsensusCore` gains borrowed forms, `propose_slice` and `ready_into` over a node-kept `ReadyBuf` whose vectors and entry buffers are reused, and `drive_into` drives a core through them; the defaults keep every existing core as it was. The allocation probe attributes its counts to the stage of each call (leader append, send, receive, persistence acknowledgement, commit advance, application), and both evaluation adapters fill the Ready in place, so the C5 allocation gate no longer charges a candidate for the harness interface's owned vectors (plan issue 073, karyos#691).
- The evaluation adapters take a batch entry cap as a const parameter: `RaftRsBatch16` (a byte cap of 16 encoded entries of W1's 32-byte allocation case, from startup) and `OpenRaftBatch16` (`max_payload_entries` at most 16, under declared limits too) hold an append to W1's frozen batch limit of 16 entries; `tests/batch.rs` observes every append, a returning follower's catch-up included, against 16 entries and 16 KiB, and the allocation test measures them (karyos#691).

- `make libkaryos-release-check` builds the two release artifacts, `libkaryos` without `karyosd` and `karyosd` alone, from a clean tree with their `SHA256SUMS`, and runs the conformance suite against the `libkaryos` archive itself; a CI job runs it on x86_64 and aarch64 Linux. Nothing is signed or published: that stays the release key custodian's step (part of karyos#700).

- The Archive's retention operations through the agent (M12; part of karyos#701): `karyos-agent` serves `legal-hold RECORDING [REASON]`, `hold-release RECORDING [REASON]`, `purge RECORDING BEFORE [REASON]` and `seal-verify RECORDING`, each journalled before it is sent and after it is answered, with its operator, the relay that carried it (karyos#708) and its parameters digest, under new journal kinds 9 to 16 (the existing codes are unchanged). A hold is sent even when the journal is unavailable; a hold release and a purge refuse without a durable request record. A hold needs an operator, a risk officer or an administrator; a release and a purge need an administrator; any role may verify. Refusals and integrity outcomes are the Archive's, reported verbatim, through the new `karyos_agent::retention::RetentionBackend` trait, called on a worker and waited for at most the guard timeout so a slow Archive never holds the agent's polling thread (an answer that does not come in time is journalled as unknown, and a call still running answers `busy`). The `karyos-agent` binary attaches no backend yet: until the Archive's control commands of karyos#967 exist, these requests answer `no archive`.

- `karyos-control`, the control-plane component that serves the agent's API v1 to remote services over HTTPS. It accepts TLS 1.3 only, requires mutual TLS, and pins each service's certificate. It relays each request to the agent's local socket as the authenticated principal. It is not part of the default build, and `karyos-agent`'s dependencies are unchanged (karyos#708).
- `karyos-agent` accepts relayed requests from the uids named by `--relay`, for the principals of `--principal`. Each principal takes its role from the agent's own table on every request. A relay cannot grant a role, and its own role never applies to what it carries. The operations journal records the relay and the requester as separate fields. The local uid mode is unchanged (karyos#708).
- `karyos-control` accepts agent-audience access tokens from a configured OIDC issuer. People sign in through the authorization code flow with PKCE in the console. A token is verified on every request against the issuer's key set: signature, issuer, audience, type, expiry, scope and principal. Only the principal is relayed. The key set is fetched over TLS 1.3 and trusted for the lifetime the issuer gives it, never longer. When no fresh key set can verify a token, the token is refused with 503 (karyos#708).

- `karyos-agent` stops cleanly on `SIGTERM` or `SIGINT`: the signal only sets a flag (`signal_hook::flag`), and the serving loop then writes the durable `agent stopped` journal record and exits 0, so the next start records no unknown interval. The stop is bounded by the new `--stop-timeout-ms` (default 5000): past it the agent exits with status 3, a second signal exits at once with status 1, and a stop record that cannot be made durable exits 1; each leaves an unclean stop. `signal-hook` is now a dependency of the `karyos-agent` package (owner item 55, karyos#710).

- The management agent changes a guarded stream's rate policy (R-CORE-21, karyos#740): the API v1 request `rate-change DIR STREAM_ID SESSION_ID EXPECTED AUTHORITY MSG_RATE MSG_BURST BYTE_RATE BYTE_BURST [REASON]`, served for an operator, a risk officer or an administrator on the safety path and for an administrator only on the administrator's path, and relayed by `karyos-control`'s `POST /v1/request` as every v1 request. Each change is journalled as a request (kind 17) and an outcome (kind 18) with the stream, the version it replaces and the version after it; an administrator's change needs its request durable first. The view's `rates` lists the version each changed stream was last answered with, and the capability `rate-change` is listed.

- A guarded stream's rate policy changes over the control path (R-CORE-21, karyos#740): the CnC command `RateChange` (type 0x14) names the stream by key, the expected policy version, the authority (0 the safety path, 1 an administrator), the operation id, the operator and a parameters digest (`cnc::rate_parameters`), and the driver answers `RateState` (type 0x8B) with the new version, or `Error` with the existing rate codes. The driver audits each request with the client, its operator and the digest. `ClientConductor::rate_change` and `RemoteClient::rate_change` send it and complete as `Outcome::RateState`. The admission protocol version is 4 (`KARYOS_PROTOCOL_VERSION` 4, C ABI 0.1.6): a client or driver of version 3, as 0.1.0-alpha.3 published, is refused at admission.

- The sender gate holds R-CORE-21's control reserve back as capacity: a guarded publication with a reserve gets a separate control bucket of the reserve's message rate and burst and, at the largest datagram, its byte rate and burst. Cancel and resolve traffic (`SESSION_ABORT`, `SESSION_ABORT_ACK` and `ABORTED`, classified by `TrafficClass`) is charged there alone through `GuardGate::admit_control`, ordinary traffic only in the publication's buckets; control traffic past the reserve waits for its own bucket and never borrows the publication's, and a policy change leaves the control bucket as the reserve sets it (karyos#840).

- Clients attach network images with ADR-0100's parent-aware attach (karyos#844).
  - **Rust client.** It sends `AddImageSubscriptionOf`, naming the network subscription each image was announced to, so the reader adopts its awaiting cell at the image's join. A network subscription therefore reads messages offered between the publication's connection and its own attach.
  - **`ImageJoinLoss`.** The event reaches the subscription as an image change: `ImageChange::join_loss` is `Some(JoinLoss { from, to })` after the image's attach. `JoinLoss::new` and `ImageChange::with_join_loss` build them for other sources.
  - **C ABI.** `karyos_image_change` gains `join_loss_from` and `join_loss_to`, and `KARYOS_IMAGE_CHANGE_SIZE_JOIN_LOSS` (64) is its size with them. A caller with the 24 or 48 byte struct gets none, as with any sized output. This stays in C ABI 0.1.7, the version ADR-0100's batch 2 started, still unreleased.
  - **Conformance.** The `subscription.await_image` op and the scenarios that use it are kept: it still checks that the intended receiver's image exists, which connection does not mean.

- A local network subscription that exists when a network image of its key is built joins that image at its join, under ADR-0100 (karyos#844). It no longer misses the messages offered between the receiver's first status message and its own attach.
  - **Awaiting cells.** When the image table builds a lane, it registers one reader cell at the lane's join for each such subscription, before the lane reaches the receiver agent. The driver places the cells on the lane's stream at `Installed`, and drops those whose subscription went away meanwhile. A required cell holds the image's consumption at its join until the subscription attaches, is removed, or `ImageTemplate::image_join_deadline` (default 10 s) passes. An optional or observer cell holds nothing.
  - **`AddImageSubscriptionOf`** (CnC command `0x15`: sequence, image, parent, lane). It names the network subscription the image was announced to. The driver checks that the parent is a live subscription of the client for the image's endpoint and stream, refusing it otherwise with `UnknownRegistration`, and takes the role from it. The reader then adopts the parent's awaiting cell in place, as the cell's own grant export for a remote client. An optional cell that the floor passed is raised to the floor first.
  - **`ImageJoinLoss`** (CnC event `0xC9`: parent, image, lane, from, to). It is sent once to an attach that did not start at the join: an optional cell raised to the floor, an expired required cell, or a parent with no awaiting cell, which joins at the head. That join can skip data the image still retains, and the record names exactly what it skipped.
  - **The legacy `AddImageSubscription`** keeps its layout and behaviour, and never takes an awaiting cell. It withdraws its client's awaiting cells of its role on that lane, so none waits for an adopter.
  - **Versions.** The admission protocol version is 5 (`karyos::PROTOCOL_VERSION`, `KARYOS_PROTOCOL_VERSION` 5, C ABI 0.1.7), so a client and a driver of different versions are refused at `Hello` rather than on the new command.
  - **Supporting changes.** New driver counters: `image start joins`, `image start joins late`, `image start joins expired`. `LogBuffer::register_awaiting` registers an awaiting cell before a buffer's conductor is taken, and `LogBuffer::join` is public.

- `Conductor::register_awaiting` registers a cell that awaits its adopter and returns an `AwaitingCell` token; `Conductor::raise_to_floor` takes only that token, and moves such an optional or observer cell, not adopted yet, up to the retention floor, returning the range it skipped. A reader admitted in process has no token, so its cell is never moved under it. It is the karyos-sys part of ADR-0100 (karyos#844), for an awaiting cell handed over after the floor passed it. Tests show that a required cell registered when an image is built holds the image's consumption at its join until its adopter takes the same cell in place, and that the adopter reads from the join.

- `ReplayCursor::follow`: a replay that follows a recording group as it is written. At the end of the complete prefix the consumer recovers the journal again and the cursor continues from where it stopped, without reopening, giving what a replay of the closed group gives; a gap or an incomplete event stays final (R-CORE-46, karyos#881).

- `karyos::alloc_count` (facade feature `alloc-count`): a counting global allocator a product-layer test profile installs to check that a call allocates, reallocates and frees nothing on the calling thread, with no `unsafe` and no internal crate. `karyos-sys`'s `alloc_count` moves from `test-hooks` to its own `alloc-count` feature, which `test-hooks` still includes (R-CORE-48, karyos#918).

- `karyos_archive::group::diff`: the public, typed first-difference comparison of two recording group journals, `(group_seq, index, kind)`, `Identical` over the same complete comparable range, or not comparable or an error; `karyos-replay diff` now prints it, with no copy of its own (R-CORE-49, karyos#919).

- The session table's bounds are a log entry (karyos#927): schema 5 version 1, the core's own entries, with one template `SessionBounds` (sessions, window, response bytes and TTL, each nonzero) and golden vectors B-1 to B-12; schema 2 and its vectors are unchanged. `ServiceContainer::propose_bounds` lets a leader write its bounds while the log carries none, and the harness's `DeliveryServer` does so once per leadership. Equal logged bounds deliver nothing; different ones rebuild a table that has applied no registration, so a restored replica reads its bounds from the log, and stop the container with `ApplyError::BoundsDiffer` once one has.

- `trace-export` pages carry a live network journal's NT-4 facts (`network`, each fact `null` when its validity flag is clear), each live journal's `join`, and `network_journals_refused` read at the agent's attach and before and after the journal table read (karyos#931).

- Dynamic registration tests for claims the #644 series left unpinned (karyos#943): an end to end run where a silent receiver is removed at its liveness timeout and the same receiver id registers again, the pending bound refused at the ceiling plus one, the documented `InvalidLimit { field: "required" }` of `with_required`, and drop counters asserted exactly once per REGISTER.

- `RELEASING.md` records the crates.io publication decisions of 2026-11-17, the publication procedure, the ADR-0033 admission review of the `v0.1.0-alpha.3` graph and the crate name check (karyos#949).

- The immutable file attribute for sealed segments (SPEC.md §8.4, "Immutability enforcement"; part of karyos#958): `karyos_sys::fs::set_immutable` sets or clears `FS_IMMUTABLE_FL` on Linux through rustix's safe `ioctl_setflags`, with no new `unsafe`, and answers `Applied`, `Unsupported` (no attribute on that file system) or `NotPermitted` (no `CAP_LINUX_IMMUTABLE`). `karyos_archive::integrity::copies::ImmutableAttribute` is the `ImmutabilityBackend` over it: it records `ImmutableAttribute` only when the attribute was set, and `Unsupported` otherwise, never a protection that is not there. Applying it to sealed segments automatically is still pending (karyos#995).

- The running Archive seals what it records (A10; part of karyos#961): with `AgentConfig::seal_interval` set, the agent seals each durable byte of a recording in the integrity journal within the interval on its control path, seals the last range when the recording stops, and chains the catalog's start and stop records (`Catalog::collect_changes`, `Catalog::take_changes`); a range a recording's store cannot serve (a recorded gap) stops that recording's sealing only, and a failure of the integrity journal stops sealing, never a recording; a shutdown chains the stops before it replies, and the stops a restart's recovery appends are chained before the Archive reports started. `karyosd` takes `--archive-seal-interval` (default 1 s). `Sealer::untrack` drops a recording whose store failed.

- `karyos-tiering`, the Archive's object storage client (SPEC.md §8.4, "Tiered storage"; part of karyos#965), under the object storage admission record:
  - `S3Store` implements `karyos_archive::integrity::tiering::ObjectStore` over S3, signing each request with `rusty-s3` 0.11.0 (`graviola`) and sending it with `hyper`'s HTTP/1.1 client over `tokio-rustls`, TLS 1.3 only, with the server verified against the configured roots.
  - It writes under object-lock `COMPLIANCE` retention when configured, and checks the TLS provider's CPU requirements first.
  - The crate is not a default member, `karyos-archive` does not depend on it, and `make tiering-graph-check` (in `pre-push`) runs the record's `cargo tree` checks: no client crate in a data-path or default graph, and no native crypto or C build in its own.

- The running Archive signs its integrity journal's heads (A10; part of karyos#966): `ArchiveHandle::spawn_signing` takes an `ArchiveSigning` (trust root, journal id, `SigningConfig` and a `HeadSigner`), offers the journal's head on the agent's control path at most once a second, asks the signer without waiting on it, and records each head the replayed key registry trusts in `heads.kyh`, so `karyos-catalog verify` can verify a running Archive's recordings. `karyosd` takes `--archive-signer <program>`, `--archive-signer-key <hex>` and `--archive-trust <file>`: the operator's program is run as `<program> sign` on its own thread, given the head's signed bytes in hex and answering the signature in hex, with custody declared. `--archive-anchor-interval` is recorded as the signing configuration's coverage-lag threshold; its enforcement and reporting are tracked in karyos#985. A head is offered only once the registered key is in force for it.

- The Archive's control protocol carries the retention operations (ADR-0088, Proposed; karyos#967): requests `HoldRecording` (6), `ReleaseHold` (7), `PurgeRecording` (8) and `VerifyRecording` (9), the response `RangeOutcome` (104) with the verifier's outcome and reason bits verbatim, and the `ControlResponse` codes 6 (held without evidence), 7 (held in memory only) and 8 (refused, the reason's name in `message`). The control server serves them from a `RetentionControl` a host attaches with `ControlServer::with_retention`, and answers code 1 without one. `karyos_archive::client::retention::RetentionRequester` sends them, and the management agent's `archive_retention::ArchiveRetention` implements its `RetentionBackend` over them; `karyos-agent` attaches it for the first configured Archive.

- The Archive's control protocol gains schema 1 version 2, the read-only retention state query of ADR-0101 (karyos#967): `RetentionState` (template 10) names a stream of the requester's own, and the Archive answers there with a `RetentionDescriptor` (105) per recording (its hold: none, held, pending or unknown; its recorded close time; the earliest policy expiry from it; the policy) and a `RetentionSummary` (106) with the `--archive-min-free` floor and the free bytes. The shared response stream carries at most a version 1 refusal, so no version 1 reader decodes a version 2 page; a version 1 Archive answers code 5. `karyosd --archive-control <req>,<resp>[,<state>]` configures the stream, and the management agent (`--archive DIR=REQ,RESP[,STATE]`) reads it after each catalog listing and shows it in its view and JSON as `catalog.retention`. The agent asks over its catalog lister's own handles, with correlation ids of its own that go on across refreshes; it shows a page only when the summary's count matches the descriptors that arrived, and a version 1 Archive (no state stream, code 5) as "retention state unsupported by this Archive".

- The Archive agent answers `HoldRecording`, `ReleaseHold`, `PurgeRecording` and `VerifyRecording` from its own retention engine and seal verifier, so `karyosd --archive` serves them end to end: the operations journal and pending holds ledger live in the archive directory, a purge is refused `legal_hold` under a hold and `no_policy` until a purge policy is configured, and a verification reports each range of the recording (karyos#967).

- The agent seals its operations journal: each durable append seals the recording to its durable end through an integrity journal in the journal's directory, so `karyos-catalog verify` reports its ranges. A failed seal stops the sealing until restart and counts in `Journal::failed_seals`; the journal goes on. `Recorder::read` reads a recorder's store back for such a seal (karyos#985).

- The Cluster log seals its committed bytes through an integrity journal in its directory, never past the commit's entry, and an install starts a new seal subject before it cuts. At a takeover, a log recovered below its seals is refused with `LogError::ShortenedBelowSeal`, naming the lost range, before anything is written (karyos#990).

- `karyos_trace::clocks::utc::UtcReference`: the UTC reference record of ADR-0090 (type 2 in the calibration journal, 18 words), with every typed refusal, the bound to UTC in nanoseconds and the conversion of a clock time to UTC for TAI, GPS, stepped and smeared (centred included) scales over the IERS Bulletin C leap table (through Bulletin C 72, July 2026), `no_evidence` where the evidence cannot say. Vectors U-1 to U-8 pass byte for byte (karyos#991).

- A purge releases the immutability of each segment it removes, through the backend `Retention::set_immutability` sets, only after every retention check passed and right before the deletion; a failed release deletes nothing. `CopyCatalog::record_enforced` records a sealed segment's copy with the enforcement its backend applied, and `SegmentStore::segment_files_below` names the segments a purge removes (karyos#995).

- `karyos_archive::replication`: schema 6 version 1 of ADR-0091, recording replication between Archives: `ReplicateRecording`, `StopReplication`, `RecordingBytes`, `SourceSeal` (the seal record verbatim, open and closed segment kinds only) and `ReplicationStatus`, with their rules, and the source's `check_request` (requests start and end on seal boundaries) and the replica's `check_seal`. Vectors P-1 to P-6 pass byte for byte (karyos#996).

- `karyosd --replica <rec>,<source-ip>,<bind host:port>,<stream>` accepts a recording pushed by a source Archive (ADR-0102; karyos#1113). The replica follows only the newest incarnation of its authorized source on the stream, and drops messages naming another recording. It ignores payload until the request's `streaming` status. It stores what arrives in `<archive>/replicas/<rec>` through `Receiver`, and counts a range only once its seal verifies, recorded with the profile it arrived under. A source start above the replica's last verified range is committed as a durable gap before the first range. Lag reads unknown before any status and after 3 s without one. An interrupted replication raises a warning and a counter. It needs `--replication-trusted-network`, `--archive-copy-location` and `--network on`.
- `EmbeddedDriver::network_image_from(stream_id, source)`: the newest exposed network image of a stream from a source address.

- `karyos-archive` restores an offloaded segment (ADR-0104, decision 6): `Tiering::restore_segment` gets the segment just below the start from object storage, checks the index object against the offload record's digest and each range against its seal, and `SegmentStore::restore_below` writes the data file and the original index verbatim under temporary names, refuses them unless the recovery scanner keeps them whole, renames them into place and lowers the start durably, never below the offload floor. The restore record (kind 10) is chained and the local copies count again only after that; a lowered start whose record a crash cut short gets it on the next reconcile, and recovery removes a restore's temporary files (karyos#1113).

- `karyos-tiering offload|restore|verify`, the offline tiering binary (ADR-0104): it takes the Archive's own locks without waiting and refuses a directory a running `karyosd` holds; it refuses while any purge intent is unresolved and for a recording with a legal hold in any state; under a retention deadline it reads back each object version's lock (a HEAD of the exact version) and skips the segment unless it is governance or compliance retained at or past the deadline; it checks `--location` against the location the Archive recorded for its own copies and refuses the first tiering commit of a directory without `--accept-downgrade-break`. Configuration comes from flags only and credentials from the file `--credentials` names, never from the environment. `verify` reports each object `verified`, `missing` or `corrupt` and downgrades a missing or corrupt copy (karyos#1113).

- The AF_XDP copy-mode groundwork of ADR-0038 (karyos#629): the XDP program source `bpf/karyos-xdp` (outside the workspace) with its pinned chain (`aya-ebpf` =0.3.0 from its committed lock, `nightly-2026-11-10`, the `bpf-linker` 0.13.0 release binary checked by digest, image `rust:1.99` by digest), the recipe `scripts/xdp-object.sh`, the committed object `karyos-io/src/xdp/karyos_xdp.bpf.o` with its provenance manifest and notices, reproduced bit for bit on x86_64 and aarch64 hosts, and a `workflow_dispatch` job that rebuilds and compares it. `karyos-io` gains the `xdp` feature (Linux, `aya` =0.16.0) with `xdp::load`, which takes the object through the kernel verifier; `deny.toml` takes the record's scoped `foldhash` 0.2.0 Zlib exception.

- `karyos-io` feature `uring` (Linux): the `io_uring` TX half `uring::tx::UringTx` with one copied `IORING_OP_SENDMSG` per permitted item, `Release::Deferred` and a `SendResult` plus `Released` pair per completion, SQPOLL off unless configured, `cancel_submitted` and a bounded reset that keeps every slot the kernel still owns and reports it (`retained`), over the `RingOps` seam with its scripted double, and the send parking probe (karyos#639). The `io-uring` 0.7.16 dependency follows its R8 admission record. `SendError` gains `WouldBlock`, `NoBuffers`, `PeerRefused` and `Cancelled` for completed sends the kernel did not transmit. `scripts/linux-test.sh` takes `KARYOS_LINUX_SECCOMP` and passes `KARYOS_URING_REQUIRED` through.

- `karyos-io` feature `uring` (Linux): the `io_uring` RX half `uring::rx::UringRx`, one multishot `IORING_OP_RECVMSG` over a provided buffer ring (`IORING_REGISTER_PBUF_RING`) whose buffers go back to the kernel only after the completion that named them was reaped and lent, reposted when the lend returns or unwinds (karyos#640). Truncated and oversize datagrams are dropped, buffer exhaustion (`-ENOBUFS`) is counted and re-armed, and `reset` cancels the arm and re-registers the pool with every buffer posted once more.

- The `io_uring` completion model of `karyos-sim` (`tests/uring_model.rs`, karyos#641): seeded runs complete the TX and RX operations of the `io_uring` backend in random order with random results, cancels and resets, and fail on a frame touched while the kernel owns it, a leaked slot or buffer, or a wrong recovery after a reset; a mutant that releases at submission is caught. `karyos_io::uring::select` opens `io_uring` with an explicit `io_uring_or_sockets` fallback (`Fallback(reason)`, a counter, the cause kept) and fails a required `io_uring` instead of falling back. `ci/seccomp/io-uring.json` is Docker's default seccomp profile plus the three `io_uring` calls, for `KARYOS_LINUX_SECCOMP`.

- `karyos-sbe`: SBE 1.0 framing over IronSBE 0.9.1 (karyos#646). Codecs generated at build time from Real Logic's public example schemas (`Car`, versions 0 and 1: repeating groups, a nested group, variable data, enums, a set, composites, constants) encode the reference SBE tool's bytes exactly; `decode_car` reads a message in place, allocating nothing, and refuses a schema, a schema version or a template this build does not know with a typed `FrameError`, never reading it as a known one. A frame cut anywhere inside the message, its repeating groups, nested groups and variable data included, is refused (`FrameError::Incomplete` or `FrameError::Decode`), never read in part. The golden vectors come from sbe-all 1.42.0 and an independent derivation from the SBE 1.0 specification, which agree byte for byte; `crates/karyos-sbe/tests/vectors/README.md` says how to reproduce them.

- `karyos-sbe`: the SBE feed adapter (karyos#647). `adapter::SbeFeed` takes one SBE feed on its two lines, frames each message by its SBE message header against the feed's `SbeSchema` (a frame of another schema, of a version this build does not read, cut inside its root block, or incomplete by the feed's `SbeSequence::complete`, is refused and counted before arbitration, so a truncated copy never wins over the whole one), reads its epoch and sequence through the feed's own `SbeSequence` extractor, and arbitrates the lines with `karyos-feed`: each sequenced message once, in order, with its header and frame borrowed for the client to decode in place. A steady cycle allocates nothing. Registering schemas in Archive manifests is not part of it: it follows with the Archive in M03. `karyos-feed`'s `Arbiter` gains a `sequencer()` accessor for that check.

- `karyos_protocol::network::authenticated` decodes and encodes the bodies of GUARD (STATE, STATUS_CHALLENGE, STATUS), SESSION_ABORT and SESSION_ABORT_ACK, following quantstratum-docs `karyos/design/authenticated-control-schemas.md` and ADR-0107. It reproduces that design's 5 blind positive vectors byte for byte and the first error of each of its 11 negative vectors. `decode_bare_status_challenge` accepts only a bare STATUS_CHALLENGE, for a guard authority's endpoint. The trusted decoder still returns `GatedType` for every one of these types, so nothing is enabled (part of karyos#648).

- `karyos_protocol::protection::signed` seals and opens the signed envelope of the guard and abort authority (Ed25519, `profile_id` 4, ADR-0086 sections 2 and 8). It checks every header field against the binding before the signature. `karyos_driver::authority` provides the Ed25519 signer and verifier. The verifier uses `verify_strict`, and the key loader refuses non-canonical and small-order public keys. Both reproduce the independent Ed25519 envelope vectors byte for byte. No path uses them yet: GUARD and SESSION_ABORT stay gated (part of karyos#648).

- `karyos_driver::wire_keys` parses and validates the wire authentication key files of quantstratum-docs `karyos/design/wire-key-files.md`:
  - the canonical field order, numbers and timestamps;
  - the per-purpose fields, and a profile that matches the purpose;
  - the 90-day and 180-day validity bounds;
  - canonical and not small-order authority public keys.

  It also derives the per-purpose MAC keys with HKDF-SHA-256 (RFC 5869, written over `hmac` so the PRK and every intermediate output are erased) over the `info` contexts of ADR-0086 section 4, reproducing the design's blind K-1 to K-5 vectors and its canonical parser files. Secrets and derived keys are erased on drop. The key directory, durable key state and reload are later parts of karyos#648; nothing uses these keys yet.

- `karyos-catalog export` and `karyos-catalog verify-export` (ADR-0103; karyos#668).
  - `export` writes an export of the named recordings from an Archive's own files. It carries the Archive journal from genesis to the later of the last record sealing exported bytes and its latest anchored head, with the registry rows its key registry seals commit and the heads and anchors over it, the recordings' bytes, and the policy versions and bindings it seals. `--time` adds the time evidence entries' journal and store, `--clock-records` the calibration and UTC reference records, and `--schema` codec schemas.
  - `verify-export` verifies an export offline with the trust file and anchor stores only. It exits 0 when every range verifies, 1 when any does not, and 2 when the export is refused.
  
  An exported recording verifies offline, with the Archive's directory removed, to the same outcomes as online.

- The Retention integrity contract's last case, "an export is verified offline" (karyos#670): `test_retention_integrity_export_verified_offline` exports the contract scenario's own evidence and verifies it with the external trust only, no Archive present. Every range's offline outcome equals the online verifier's.

- `RaftLog::entries_into` and `LogView::entries_into` read a log range into caller buffers: the entries and their payload buffers are reused in place and the read window keeps its capacity, so a second read of the same range within one segment allocates nothing (a read that crosses segments still allocates when the segment store reopens its reader file) (karyos#681, ADR-0105). The checks, errors, read window and metered budget are those of `entries`, which is now a wrapper.

### Changed

- `karyos-codec-derive` is publishable (`publish = true`, a README) and joins the crates.io set at 0.1.0-alpha.4, after `karyos-codec`, because `karyos-archive` depends on it (owner decision 2026-11-23). It is internal and unstable in alpha.

- The agent's reply deadline tests fill the socket's buffer before writing a bounded 4 MiB reply, instead of relying on a fixed 16 or 64 MiB reply to outsize it: a host with `net.core.wmem_default` at 128 MiB held that reply whole, so the write never blocked and both tests failed there.

- `libkaryos` and `karyosd` are released as separate artifacts, unsigned for 0.1.0-alpha.4 by owner deferral of 2026-11-23; both MANIFESTs say `signed=no` (karyos#700).

- `SegmentStore::read` keeps the last finished segment it opened and reads through that handle, instead of opening the segment's data file for every read: a catch-up scan with `RaftLog::entries` opened it twice per entry (karyos#1001). The handle is dropped before any segment file is created, cut or purged. The item 37 catch-up bench also prints the read cost per entry.

- The running Archive's signing poll reads only the integrity journal records chained since the last poll and replays the key registry only when a key registry record is chained, instead of rereading the whole journal each second (`IntegrityJournal::records_from`). `ArchiveHandle::signing_lag` reports the coverage lag, and `karyosd` logs a warning when signed coverage falls behind `--archive-anchor-interval` and when it recovers (karyos#1031).

- CRC-32C runs slicing by 8 (eight bytes a step through eight tables) instead of a byte at a time, in safe code and without a dependency: every segment write and read, the snapshot store and the log's frame check get faster per byte (karyos#1045).

- The Raft log seals its committed bytes in whole `SEAL_CHUNK`s (1 MiB) instead of at every commit advance, so the integrity journal holds one record per chunk of committed log and an open replays that many, not one per commit advance; the commit path no longer pays a journal fsync per advance. A shorter committed tail is sealed by `RaftLog::tick` once it has waited `DEFAULT_SEAL_INTERVAL_NS` (1 s, `set_seal_interval`) on the host's clock, by `RaftLog::close` at a clean shutdown, by `RaftLog::seal` on demand, and by a purge before it removes anything; the simulator harness's servers run the tick duty and close their logs on `shutdown`. The takeover check still refuses a log recovered below its seals (karyos#1050).

- `Propose::propose`, `Envelope::Register` and `Envelope::to_vec` document a host's obligation under ADR-0087: service entries go through `ServiceContainer::propose`, which holds a leader's registrations until the session bounds apply; raw bytes handed to the core bypass that gate (karyos#1062).

- The codec derive refuses, at compile time, two fixed fields whose byte ranges overlap (naming both) and a field past its template's block length (karyos#1066).

- Tests: the driver's rejoin test runs its sender's network clock (the agents' duty time, a test-only `Network::set_clock`; the driver's injected clock times claim deadlines only) on a clock the test holds and steps, so the registrant's removal is pinned to the sender's own liveness deadline from its last SM (still there one nanosecond before, gone at it) instead of a wall-clock bound with 100 ms of slack (karyos#1067).
- Tests: the replayed SETUP test counts each replay's drop as it is handled, instead of an exact total over the run that other control frames from the rig's real sockets could raise under host load (karyos#1067).

- A multicast subscription's CHALLENGE, and every resend of it, now leaves from the driver's unicast control endpoint, which its SOLICITs already use (ADR-0096, ADR-0097; karyos#1067). This is visible on the wire: the UDP source port of a multicast CHALLENGE is now the control endpoint's port instead of the group port, and the bytes are unchanged. Before, the drivers on one host shared the group port, so the publisher charged all their CHALLENGEs to one `setup_answer_rate` bucket. Two drivers joining 20 streams each lost 13 to 14 CHALLENGEs, and one of them bound half its streams late, through SOLICIT. A key without a control endpoint sends every CHALLENGE and SOLICIT from its arrival socket, counted as `challenges_from_arrival`. That covers a failed creation, which is counted and still admits the subscription, and the new `NetworkConfig::control_endpoint = false` (default `true`), for networks whose multipath routing hashes on the source port. A firewall that admits RSP_SETUP only from the group port must also admit the control endpoint's port.

- `karyos-client`: a network subscription holds back a retired image's change until the image's clean end is positioned (the driver announces the retirement before it positions the seal), so `karyos_subscription_next_image_change` no longer reports a clean end at position 0 when it is not (karyos#1067). It goes without a position after 10 000 adoptions.
- Tests: more load-sensitive tests from karyos#1067. The two-path driver tests wait, bounded, for the second path to bind before their first message; the min-gate repair loop is bounded by time; the one-local-gap test asks for both paths' heartbeat sources, at least; and the tool attach rollback test checks that no descriptor is left open instead of comparing counts, which a previous test's late close could lower.

- Tests: the karyos-tools verify tests route their last direct integrity journal open through the bounded retry. A child another test spawns shares the journal's `flock`ed file description until its exec closes it (macOS included), so an open right after a drop can see `Locked` for that instant (karyos#1067).

- The agent seals an unsealed operations journal in chunks of at most 1 MiB, each read and sealed on its own, instead of reading it whole on its first seal (karyos#1071).

- Tests: a journal recorded as an Archive recording, shaped as a sequencer's admission journal, is sealed and verified by the running Archive like any recording, and a changed byte of one of its entries no longer matches its seal (karyos#1088; SPEC §8.4, "Sealing and tamper evidence"). The journal's producer, the Sequencer, lives in its own repository.

- The Archive's signing poll keeps only the journal records not yet covered by a signed head (and the key registry records the registry replay reads), dropping the covered prefix, so its cache no longer grows with the journal; `HeadSigning::poll_from` and `HeadSigning::covered` let a caller sign over such a window (karyos#1095).

- `ContainerConfig::session_budget` and `ApplyError::BoundsUnheld` document that every replica must use the same session budget: a replica with a smaller one stops at the logged bounds with `BoundsUnheld(OverBudget)` while the others go on (karyos#1097).

- `AgentError::ImagesOfAnEarlierRun` documents what an operator sees after a restart (the group's restart is refused and the earlier journal stays replayable) and how to continue: start the group as new in a journal of its own, in a new directory or under a new group id, with `first_group_seq` set past the earlier journal's complete prefix (karyos#1099).

- Guarded concurrent publications through the C ABI, part (e) of karyos#1102 (ADR-0092). This lifts GC-7 for guarded concurrent publications.
  - **`karyos_publication_poll_outcomes`** on a concurrent handle delivers the records of its own blocks on lane 0 when its stream is guarded. Before, a concurrent handle always had none. Any other lane stays `KARYOS_E_INVALID_LANE`.
  - **Offers and claims** of a guarded concurrent handle report `KARYOS_E_GATED` and `KARYOS_E_RATE_LIMITED` as an exclusive handle's do. Before, they reported an unknown client error.
  - Timed lanes stay exclusive: a schedule on a concurrent stream is still refused.

- Every recording group journal record, and the Archive control messages that were still written by hand (`RecordingRequest`, `PurgeRecording`, `RangeOutcome`), are derived with `karyos-codec-derive` (karyos#1104); `ControlMessage`, the dispatcher, stays written by hand; their wire encoding is unchanged and every existing vector decodes and encodes exactly. The derive gains what they need: a versioned message (`#[message(versioned)]`, a `decode` taking `v2: bool`) whose `#[field(offset = N, since = 2)]` fields read as their default from a version 1 block; reserved bytes (`#[message(zero = [(OFFSET, WIDTH), ...])]`), refused unless zero; variable tied fields (`#[field(with = PATH, spans = [...], var)]`), read with the decoder in the variable fields' order; tied fields written from the whole message, so two fields that share a byte are written together; and a block several templates share (`#[message(templates = [PATH, ...])]`), checked against each and encoded as the template its caller passes. `MessageEvent` now declares `payload` before `extension`, the order of their bytes on the wire.

- The codec derive takes a tied field, `#[field(with = PATH, spans = [(OFFSET, WIDTH), ...])]`: one value whose bytes sit at block offsets that are not adjacent, read through `PATH::read(&block)` and written through `PATH::write(&mut encoder, &value)`, with every span checked against the template's block length and against every other field (karyos#1104). `StartRecording`, `Replay`, `RecordingDescriptor` and `RecordingSignal` are derived with it; their wire encoding is unchanged and every existing vector decodes and encodes exactly.

- `VerifyRecording` runs on a worker thread of its own: the agent gathers the evidence, and the worker reads the sealed ranges through a read-only view of the recording's store and answers, so a long verification no longer holds the recorders or the replays. One verification runs at a time; another is answered with an error to retry (karyos#1111).

- A replica now verifies a seal on its own stored bytes before it touches its copy catalog, and never downgrades a verified copy for anything the source sends (ADR-0102 decision 5; karyos#1113). `Receiver::bytes` no longer records an arrival: bytes at positions already stored are compared instead of written (identical bytes are `Arrival::AlreadyStored`, differing ones `ReceiveError::Mismatch` and never overwrite), and bytes past the tail are refused as `ReceiveError::PastTail`. A seal that verifies for a range already counted returns `Verdict::AlreadyCounted` with no catalog change, and one that does not verify records nothing. `Replica::arrived` and `ReplicationError::NotArrived` are removed; `Replica::invalidate` downgrades verified copies on the replica's own failed check only.

- A continuous replication's steady duty allocates nothing on the source (karyos#1113, karyos#996). `Outgoing::Bytes` carries a `Chunk` that derefs to its bytes and gives its buffer back to the `Sender` once dropped, so each chunk reuses a pooled buffer; `Sender::poll` finds the next range without collecting; the agent reuses its journal and message buffers, reads new seals through the new `IntegrityJournal::records_from_into`, and drops the seals already sent.

- The Archive's control server reuses the buffers of the answers it has sent, and the batch each replication forwarding pass takes, so forwarding a running replication allocates nothing (karyos#1113). Before, every forwarded replication message allocated an encoding buffer, and every forwarding pass allocated a batch.

- Tests: a loop test pins that an Archive shutdown releases a sealed group directory's integrity journal lock before it returns, and the `karyos-tools` verify tests retry every integrity journal open on `Locked`, which a sibling test's child process could hold for the instant between its fork and exec (karyos#1148).

- Under Miri, the revoked reader loss test stops once every slot was rewritten and the command ring in-order property runs at most 24 steps; native runs keep their counts (karyos#161).

- A C ABI test shows that a driver with its network refuses a concurrent publication on a `karyos:udp` channel with `KARYOS_E_UNSUPPORTED_CHANNEL`, writing no handle. ADR-0099 keeps timed lanes exclusive on this refusal (karyos#177). The Rust facade's case was already covered.

- `TraceReport::out_of_scope` takes the lane a declaration applies to (`None` for every lane), and `karyos-trace` scopes a recycled journal's boundary to that journal's own lane, so a multi-lane aggregate's other lanes stay in scope (karyos#185).

- Recording group records are schema 3 version 2 (ADR-0089, karyos#672): the message, lifecycle and loss events carry `image`, the registration of the network image they came from (0 for none), so two images of one `karyos:udp` alias are recorded, delivered and replayed as two. Version 1 journals are still read, as image 0, with the coarse identity of before. The Gateway's `Event::Message`, `Event::Loss` and `Event::Lifecycle` gain `image`; the client's `ImageStop` and `SubscriptionError::Poll` gain `image: Option<u64>`, `MessageInfo` gains `image`, and `ImageChange` gains `registration` (with `ImageChange::with_registration`). `wire.group_record` is 2.
- A group capture no longer continues a journal that already holds network images (`CaptureSetup::ImagesOfAnEarlierRun`): registrations are unique within one driver incarnation only, so a later run could repeat one and replay would merge two images (ADR-0089 decision 5, review of #1090). Such a group continues in a new journal.

- `include/karyos.h` is generated by cbindgen 0.29.4 from `karyos-ffi` and `crates/karyos-ffi/cbindgen.toml`, with item 48's static inline initialisers in its trailer; `make header-check`, part of `make pre-push`, regenerates it and fails on any difference, and `make header` rewrites it. The ABI is unchanged: the same 17 struct layouts, 133 constants and declarations; prototypes now spell struct parameters `struct karyos_*` (karyos#697).

- The driver publishes its configured `max_trace_points_per_client` and `max_trace_point_registrations_per_client` as the gauges `trace points per client` and `trace point registrations per client`, and the management agent's `limits` answers them for `trace.points_per_client` and `trace.point_registrations_per_client` instead of the defaults; with no attached driver the defaults stay (karyos#868).

- The driver keeps its own copy of each application trace point in the driver counters region, which clients never write (type id 8, the point's name as its label, keyed to its client, its id as its value), freed with the point; `trace-export` names `points[]` from that copy, so a client rewriting its own cell's value no longer changes an exported name. The agent's sample and `karyos-stat` leave these cells out of the driver counters (karyos#869).
- The copies have cells of their own: the driver counters region grows by `max_trace_point_copies` (256 by default, `karyosd --max-trace-point-copies`), and a point registered past it gets no copy, is exported unnamed and is counted in `trace point copies dropped`, so copies never take the cells of the driver's counters or positions (karyos#869).

- A driver now refuses to start, with `InvalidConfig`, when `AgentConfig::receiver_bindings` is below `max_destinations`, for every configuration and not only one with a dynamic publication (karyos#947).

- `karyosd --archive` now requires `--archive-anchor-interval` and refuses to start an Archive without it (karyos#961): SPEC.md §8.4 makes `anchor_interval` required configuration with no default (X14). An existing invocation of `karyosd --archive` must add the option. The value is validated now and takes effect once the head signer of karyos#966 runs.

- Tests: the mixed-version Archive test waits for its 1000 recordings' signals, the page and the replay by deadline, not by a count of duties, so a loaded host no longer fails it with a short count (karyos#967).

- Changelog fragments are exempt from the SPDX line rule and start with their section header, as `scripts/changelog-assemble.sh` requires (karyos#972).

- `karyos-catalog verify` returns typed errors (`VerifyError`, `UsageError`, `TrustError`, `StoreError`) that keep the path and the underlying error; they become text only at the command boundary, with the same messages and exit statuses (karyos#974).

- Registration limits are refused at driver start where they used to be accepted (karyos#977, design 11.2): `MAX_REGISTRATION_TABLE` falls from 65,536 to 4,096 entries; `registration_pending` must be at most `registration_rate` times `join_timeout` in seconds (1,280 with the defaults, 256 per second for 5 s), the design's configured sizing rule (the total rate bucket starts with burst credit, so it is not a bound the limiter enforces); and `join_timeout` and `registration_refusal_interval` must be at most 60 s (`MAX_REGISTRATION_INTERVAL`). A configuration past any of them is refused with `RegistrationConfigError::InvalidLimit` naming the field, not clamped: a silently smaller table would change the bounds an operator sized for. The defaults are unchanged and pass.
- CnC counter ids move (karyos#977): the new sender cells follow the 26 existing sender cells, so every cell the driver allocates after them gets a new id: the receiver cells move by 9, and the spin meters and later cells by 12. No existing label changes, the counter record layout (`LAYOUT_VERSION`) is unchanged, and readers that find cells by label, as `karyos-agent` and `karyos-tools` do, are unaffected; a reader that indexes cells by id must look them up by label.

- `karyos-trace`: `TraceReport::add_subscriber` and `add_subscriber_source` take the subscriber journal's `Lane`, and a subscriber journal is expected only for messages of its lane, so a lane-0 subscriber no longer leaves a lane-1 trace `Incomplete`; single-lane reports are unchanged (karyos#992).

- The bench smoke tests' wire child exits with a failing status and one line on standard error instead of panicking (karyos#993). The fault tests make a child fail on purpose ("receiver stopped before the sender finished"), so a passing run no longer shows a `panicked at` line that reads as a failure. The parent still judges each child by its exit status, as it does for the `karyos-bench` binary's child.

- `karyos-trace` is publishable (`publish = true`, a README) and joins the crates.io set from the next alpha, after `karyos-protocol`, for karyos-insights (ADR-0068, INS-Q4). Its analysis surface, the trace report, journal sources, histograms and clock calibration and the types their signatures name, is supported in alpha; the rest of the crate, its writers, collectors, agents, sampling and trace clocks, stays internal and unstable (karyos#997).

- `RaftLog::entries` reads frames the index places back to back in windows of up to 1 MiB instead of two reads per entry, still checking every frame: reading 1 GiB of 256 B entries back for catch-up drops from 0.68 to 0.14 µs per entry on an unloaded host (karyos#1001).

- Copy records keep the arrival profile (`ArrivalProfile`) in a byte version 1 kept reserved, and gain the state `Gap`. A record written before reads as `Local`.

### Removed

- The unused `karyos-sim` dependency of `karyos-tools`, so nothing added to `karyos-sim` enters the shipped `karyosd` graph (karyos#926).

### Fixed

- A reply to a REGISTER or a first SM whose send latches a fault on a destination's control queue (an `EMSGSIZE`, say) no longer leaves that fault in place: the queue is evicted, and the destination's next control opens a fresh one instead of stopping at the fault and being dropped. Ordinary backpressure keeps cancelling the unsent reply in place (karyos#1016).

- `karyosd --archive`'s head signer keeps ownership and identity while it ends a signing program (karyos#1017): a request whose reaper thread cannot start is kept and retried, and no new program starts meanwhile; on Linux the worker reads the program's output without blocking and is cancelled, so a descendant outside the signer's process group that holds the output open no longer blocks every later request; and the program's success is read with `waitid(WNOWAIT)` (Linux, through the new `karyos_sys::child`), so it is reaped only after its process group is killed and the kill can never reach a reused group id. The group test no longer depends on the host reaping orphans.

- `SessionTable::new` checks every table's byte size against what `Vec` can address before it reserves any of them, so bounds past the address space are refused without filling the smaller tables first; on a host that overcommits memory the old order could grow a table page by page until the OOM killer stopped it (karyos#1026).

- `scripts/linux-test.sh` now runs on hosts whose `tr` is uutils coreutils (Ubuntu 25.10 and later; karyos#1032): the character set that names the tree ends with `-`, so `.-\n` is no longer read as a reversed range.

- `karyos-ffi`'s conformance tests build the admission stub and `karyosd` (or bring them up to date) once per run, in a target directory of their own, instead of reusing whatever binary is in the shared one, so a stub of an older protocol version no longer fails `op-connect-other-version` with `protocol` (karyos#1063).
- The head signer's tests wait until each program they write can be executed, so a concurrent test's fork no longer fails it with `ETXTBSY` (karyos#1063).

- A redundant path joins its own NAK control group: each later path of a reliable multicast subscription joins the group the driver's control group table (or the channel's `nak-control`) names for its interface, the image binds it when the path is bound, every NAK is copied once to each distinct path group, and peer NAKs on any of them feed the image's suppression state. Before, only the founding path joined a control group (karyos#1064).

- The retention-floor e2e tests (`an_optional_receivers_*` and `a_slow_optional_receiver_under_min_is_bounded_and_repaired`) no longer fail on a loaded host because of datagrams the host really loses (karyos#1067). The sender used to hold back every NAK so that C's planted hole stayed open, which left B's and C's real losses unrepaired. It now holds back only C's NAK for that hole. The hole is planted by term offset instead of by arrival count, which an earlier real loss shifted. `pump` waits up to 30 s instead of a fixed number of duties. A failure now prints every driver's counters, its receive sessions, a trace of what each receiver saw, and the NAKs the sender answered.

- Two `karyos-sys` IPC tests no longer fail intermittently on a busy test process (karyos#1067): `readable_reports_a_pending_message_and_a_closed_peer` and `the_transport_accepts_zero_or_one_descriptor_and_rejects_the_rest` wait, within 10 s, for the peer's close after dropping its end. A test running in parallel that spawns a child forks a copy of every descriptor, so the dropped end can stay open until that child execs.

- A NAK control group entry a channel's `nak-control` adds to the driver's table is counted per subscription key and leaves the table with its last user, so channels naming more than eight distinct groups over time no longer exhaust it; configured entries stay. A key joined to an entry counts it even when its own channel has no `nak-control`, and a second handle of a key whose `nak-control` names groups the key did not join is refused with `DriverError::ControlGroupConflict`. `EmbeddedDriver::network_control_groups_in_use` reports the entries in use (karyos#1086).

- `karyosd`'s head signer test of a descendant outside the signer's process group runs on Linux only, where the output read is cancellable; elsewhere the read blocks by design, so the test failed `make pre-push` on macOS (karyos#1091). Off Linux, a signing program reaped by `try_wait` is no longer signalled through its process group afterwards, whose id may have been reused (karyos#1084).

- `a_release_that_clears_nothing_is_an_error` calls the inherent `ImmutableAttribute::release`, which refuses a file system with no attribute, and checks the backend's release separately (nothing to release there: `Ok`); both go through one clearing function. It failed in Linux Docker since karyos#995 (karyos#1094).

- A guard close's abort pass on a concurrent buffer (`Conductor::abort_marked_claims`, karyos#1102) aborts the claims it observes in the same call. Before, a claim the pass observed but did not abort kept a first-seen time of `u64::MAX`, so a later deadline service read the clock as going back and restarted that claim's deadline.

- With sealing on, the Archive refuses a recording group whose journal directory is the Archive's own (`AgentError::GroupInArchiveDirectory`, naming the directory), before the journal exists: that directory's integrity journal is the Archive's, so the group's journal was silently never sealed (karyos#1112).

- karyos-ffi's tests give their client conductors an hour's driver timeout under Miri, as karyos-sim's and karyos-driver's do: under the interpreter the embedded driver's heartbeat could stall past the 10 s default, the client gave the driver up as lost and a pending add failed as `KARYOS_E_UNKNOWN` (karyos#1117). `tests/connect.rs` and `tests/outcomes.rs`, the cross-process client's tests, are compiled out under Miri, as MIRI.md already states they run natively only.

- The Archive's verification worker clears its "verification runs" flag before it sends the answer, so a client that posts the next `VerifyRecording` the moment the first answers is no longer refused as busy; the flag is still cleared on a panic (karyos#1135).

- With sealing on, a group journal directory is compared with the Archive's own as a canonical path, so a relative path, a `..` detour or a symbolic link to the Archive's directory is refused like the directory itself, and the group's integrity journal is keyed by the canonical path; a directory that does not resolve is refused with the new `AgentError::GroupDirectoryUnresolved` (karyos#1140).

- A guard close on a concurrent guarded stream labels its aborted blocks by position (karyos#1141). Before, it labelled them by count, as the next aborted blocks the walker read, so a block its writer aborted just before the close could carry `GUARD_CLOSED` while the block the close aborted carried `WRITER_ABORTED`. Only the reason label could be wrong; no record was lost. `Conductor::aborted_positions` gives the stream positions of the blocks the last deadline service call or guard close pass aborted.
- A guard close's abort labels are kept in storage reserved when the stream is guarded (`Conductor::max_aborted_positions` per pass), so labelling never allocates on the abort path. A deadline service call that a fault injection ends early reports no positions of an earlier call.

- With sealing on, a group start is refused with `AgentError::GroupDirectoryUnresolved`, naming the Archive's directory, when the Archive's own directory no longer resolves (moved or removed while it runs), instead of skipping the comparison and admitting the group (karyos#1149).

- `make miri` no longer aborts in `karyos-ffi`'s conformance tests (karyos#161): `the_runner_keeps_its_karyosd_client_served_between_scenarios` reads the suite's files, which Miri's isolation forbids. It is now ignored under Miri, as the conformance tests beside it are.
- `make miri` runs in three parts, `miri-sys-log-buffer`, `miri-sys-rest` and `miri-ffi`, and CI runs each as its own job with a 6 h limit (karyos#161). The full run took about 10 h on a shared Linux host, beyond one job's limit.

- An index shortened by media damage no longer drops sealed events silently at an Archive restart (u5; part of karyos#671): with sealing on, the agent compares each recording a crash left open, as A2's recovery kept it, with what its seals cover. One recovered below its seals is reported as `Event::IndexShortened` with the lost range and the first seal it breaks, and is counted by `ArchiveHandle::shortened_indexes`. An unindexed tail above the last seal is still an unacknowledged write. `integrity::damage::shortened_below_seal` is the check.

- A `control-mode=dynamic` network publication now holds the routes, queues and TX slots of `max_destinations` destinations of its endpoint from its admission, and is refused with `DriverError::EndpointCapacity` when the endpoint cannot hold them (karyos#915, design 3.5): its registrants open their routes on the sender thread, where no admission runs, so an endpoint could otherwise be outgrown at run time. Manual multi-destination publications keep the per-destination admission of karyos#859.

- A multi-destination network publication's membership table now holds a Pending entry and a member per destination, `max_pending` and `max_receivers` raised to `max_destinations` when it is larger (karyos#917, design 3.5): at `max_destinations` above 16 the default `max_pending` of 16 could refuse destinations that CHALLENGE at once.

- `make miri` on Linux: the shared region tests of `cnc_store`, `conflation`, `diag` and `trace_mirror`, which reach `memfd_create`, are excluded under Miri as the `ipc`, `mmap` and `log_buffer` region tests already were, and so are the free space test (`statvfs`) and the two-process clock test, which Miri cannot run either (karyos#924).

- A dynamic subscription's REGISTER backoff is no longer reset by an ANNOUNCE, only by an accepted ANSWER or a bound image, so a receiver its sender cannot bind backs off up to the 1.6 s cap between REGISTERs instead of retrying at the base interval (karyos#947).

- Dynamic registration follow-ups of the karyos#942 decisions (karyos#977): IPv6 sources share their per-source bounds per /64; a dynamic publication is never announced on the setup cadence, a dead required slot included; the ERR at a first SM counts its send failure in `registration_replies_unsent`; replies to REGISTERs and first SMs take transient control routes, at most half the cache, that never evict a destination's route; the CnC gains the sender cells `registrations dropped quarantined`, `registrations dropped required lost`, `registrations dropped challenge rate`, `registrations pending replaced`, `registration source table full`, `registration replies unsent`, `receiver bindings reserved`, `challenges unbound` and the gauge `sender counters overflowed`, and the receiver cells `registers rate limited`, `setup not from control` and the gauge `receiver counters overflowed`. The new sender cells follow the 26 existing ones and the new receiver cells follow the 8 existing ones; `registrations dropped pending` and `registrations dropped source pending` stay, though they can no longer move.

- Three tests that failed on a loaded host now wait on the event they check, within a bounded deadline (karyos#993): the OIDC key set lifetime test gives its set five seconds of lifetime and waits for the refusal instead of sleeping a fixed second, the hello timeout test advances its clock until the close is seen, and the zero linger test removes its publication only once the sender's session is established.
- The `karyos-ffi` tests that open C drivers no longer fail with `KARYOS_E_HANDLES_EXHAUSTED` (300) on a host with more than eight test threads (karyos#993): the driver table holds `KARYOS_MAX_DRIVERS` (8) per process, and every such test now takes its drivers' slots from one crate-wide test pool first.

- A network publication or subscription added while an endpoint at its fixed bind address is still retiring after its last user went is refused with the retryable `DriverError::NetworkBusy`, and taken once the endpoint has retired, instead of failing with `NetworkEndpoint` on the bind (karyos#994). Endpoints bound to port 0 are not affected.

- Four tests that failed only on a loaded host now wait by deadline, not by a count of cycles, with their assertions kept:
  - `the_facade_removes_a_retired_images_subscription`: its rig waits for the driver to forget the registration, its waits are bounded at 120 s, and its client's liveness timeout matches them. The assertion now reports the stage, registrations and image count.
  - `colliding_aliases_on_one_multicast_group_keep_two_images_apart` and `a_client_sees_the_admission_change_by_event`: the e2e `pump` deadline is 120 s.
  - `a_shutdown_releases_the_group_integrity_journal_lock`: it waits for the agent's first record, written only under the lock, rather than for the file and a 1 ms sleep.

- A subscription release the client cannot submit now is tried again instead of dropped (karyos#1067). When the command ring is full or the pending requests are at their limit, the client keeps the returned handle and retries it at each service: `Client::pending_releases` counts the ones waiting. Before, the client dropped the handle and counted it in `subscription_releases_failed`, and the driver kept the registration until the client ended. Under load that left a retired image's registration in place: the cause of `the_facade_removes_a_retired_images_subscription`'s rare failure. A removal that can never be submitted is still dropped and counted.

- A steady seal no longer allocates: `IntegrityJournal::append` checked each record against a clone of the chain's state (two maps) before writing it, four allocations per seal; it now checks in place (`ChainCheck::check`) and accepts after the write. A new test counts a steady recorder, sealing and replication cycle over the real disk and asserts it allocates nothing (karyos#1113).

- The offline tiering tests build again on main: their copy record names its arrival profile, the field #1202 added (karyos#1113).

### Security

- CI pins every GitHub Action by full commit SHA, with the release tag as a comment, instead of a mutable major tag (karyos#920).

- `url` moves from 2.5.8 to 2.5.9 (with `form_urlencoded` 1.2.3) in the lockfile, for RUSTSEC-2026-0592: `Url::origin()` recursed once per nested `blob:` prefix and could overflow the stack. It reaches `karyos-tiering` through `rusty-s3`; `make deny` failed on it (found by the runtime admission check of karyos#688).

## [0.1.0-alpha.3]: 2026-11-17

### Added

- R-CORE-38, the agent API's limits (quantstratum-docs:
  karyos/design/agent-api-v1.md). A v1 request, `limits [DIMENSION=VALUE
  ...]`, answers each connection, read and write dimension as a negotiable
  bound, a fixed bound or no bound (`{"value":null}`), and refuses a
  proposal above a bound with `{"error":"above bound","dimension":D,
  "bound":N}` and one for a dimension it does not know with
  `{"error":"unknown dimension","dimension":D}`. It is stateless, so a negotiated value applies to the
  request that repeats it only. Only `read.request_bytes` is negotiable in v1,
  downwards, and applies to the request that proposes it; no bound
  changed, and a client that never sends `limits` is served as before.

- R-CORE-12, the Archive's public durable-prefix acknowledgement
  (quantstratum-docs: karyos/design/archive-durable-acknowledgement.md).
  `karyos_archive::durable` answers a recording's `DurablePosition` (the
  stream position below which every recorded byte is on storage, never
  ahead of the last successful sync) and a recording group's
  `GroupDurable` (its durable `group_seq`), as two separate types. In
  process through `ArchiveHandle::durable_position` and
  `CaptureSender::group_durable` and `durability`; remotely through
  `DurableQuery`, over the control streams with schema 4 version 1
  (`QueryDurable`, `DurablePosition`), a new schema beside the frozen
  schema 1. An Archive that does not know schema 4 answers code 5, which
  `DurableQuery` reports as unsupported, never as a durable position.
  `Described` gains `durable`.
- SPEC.md §13 "Stall isolation and capacity" with the asynchronous
  Archive among the stalled holders (karyos#673):
  `karyos-sim/tests/stall_isolation_archive.rs` pauses two optional
  readers, an observer and an `async` Archive recording inside their
  copies, loans held, with a paused claim, while a publisher runs ten
  terms: no back pressure, quarantined slots within `S`, an extra
  admission refused, and every holder, the recording included, reads the
  held bytes unchanged and is then lapped. `karyos-sys` gains the
  `test-hooks` pause point `PausePoint::LaneReadLoanHeld`, inside a lane
  reader's read with its loan held.
- SPEC.md §13 "Stall isolation and capacity" with the real network
  sender (karyos#627): `tests/stall_isolation_sender.rs` stalls two
  optional readers and an observer in their copies, loans held, on a
  reliable network publication's lane while its sender keeps up and an
  in-process publisher runs ten terms. The publisher is never held,
  quarantined slots stay within `S`, an extra admission is refused, and
  the stalled readers read unchanged bytes, then are lapped. A paused
  claim on that lane holds the in-order sender, and so the publisher at
  its window, until the claim's deadline aborts it, which a second test
  pins.
- `karyos-ffi` tests owner item 48's refusal on every sized init:
  `every_sized_init_refuses_below_its_first_version_and_writes_within_it`
  calls each of the seven `karyos_*_init_sized` one byte short of its
  first version's size, written as a literal, and at that size. The first
  is refused with `KARYOS_E_INVALID_ARGUMENT` and nothing written, and the
  second records that size and writes nothing past it, so a wrong minimum
  in one entry fails that entry. Until now only
  `karyos_subscription_options_init_sized` had the refusal tested.
- Conflation refresh and snapshot cycles (SPEC §7.1, "Refresh and snapshot
  reconciliation"; ADR-0080 in `quantstratum-docs`, its loss rule amended
  by ADR-0081; karyos#634).
  - A publisher runs a cycle on a conflated lane with
    `karyos_client::RefreshCycle`: a begin marker, refresh values of the
    keys it chooses, and an end marker, carried in ordinary messages
    through their reserved value. The frame format does not change.
  - A view whose table opts in (`ConflationConfig::refresh`) turns every
    key a complete cycle carried `Fresh`. A cycle whose range a recorded gap
    cuts (ADR-0081, even one recorded before its begin was read), replaced
    by a new begin, or ended with another begin position, count or scope
    restores no key, not even keys whose refresh values arrived. Until the
    end marker a refresh value keeps its key's freshness. Live updates
    restore their key as before.
  - Encoding and marker payload: `karyos_sys::conflation::cycle`. Writer:
    `ConflationWriter::enable_cycles`, `cycle_begin`, `cycle_value`,
    `cycle_end`, `cycle_abort`, `write_refresh_at` and `restore_at`.
  - Counters: `NetworkViewCounters::{cycles_completed,
    snapshots_completed, cycles_aborted, keys_restored, markers_malformed}`
    and the same in `FreshCounters`.
  - Tests: `a_refresh_cycle_restores_what_it_carried_and_a_cut_one_nothing`
    (SPEC §13 "Conflation refresh", end to end), and the writer's
    `a_complete_cycle_restores_only_the_keys_it_carried`,
    `a_cut_cycle_restores_no_key`, `cycles_are_matched_by_id_begin_and_count`
    and `live_updates_inside_a_cycle_are_unchanged`.

- `RELEASING.md` lists the gates a release runs, as the 0.1.0-alpha.2
  Evidence table records them, and how each result is recorded.
  `make loom-full` is now required at every release head, not only on
  pull requests that touch the counters seqlock. After a tag, its
  release notes only gain dated Evidence rows and dated errata. Publishing
  to crates.io is not decided there.
- SPEC.md §13 "Required set transitions" gains its fourth case, a
  required Archive only: `test_recording_required_alone_connects_and_bounds_until_it_leaves`
  (karyos-driver, with a shared-terms variant on Linux) runs a strict
  stream whose only required participant is a `Role::Required`
  recording. The stream is connected; the limit is the recording's
  position plus the window and never decreases; once the recording
  leaves, the limit is the head snapshot plus the window and offers are
  `NotConnected`; an optional reader leaves the limit following the
  head; a required recording joining later bounds the publisher again.
  The alpha.2 release notes list this case as missing under "Partial:
  required set transitions".
- The channel URI grammar is recorded in
  `crates/karyos-protocol/CHANNEL-URI.md`, with the rules every new key follows
  (owner decisions of 2026-10-21, "Common URI rule"; karyos#636): kebab-case
  names with one spelling, checked when `karyos-protocol` builds; the duration
  grammar, `channel::parse_duration`, which requires an `ns`, `us`, `ms` or `s`
  unit and refuses a missing or unknown unit and overflow with a typed
  `DurationError`; and `ChannelError::InvalidDuration` (code 11) for duration
  keys. A test per published key asserts the sixteen existing keys parse as
  before.
- A conflated network view closed by its terminal cell can be recreated
  (driver-internal, `EmbeddedDriver::recreate_network_view`, until karyos#637
  gives it a public way in). The new view starts with every written key's last
  value `Stale { since }` the terminal's start, and a key turns `Fresh` only
  with its own update. The receiver's seal gate moves to the new view. The
  closed table is kept until the recreation, the image's retirement or the
  driver's close, never longer. Counted as `recreated` (view counters) and
  `views_relinked` / `relinks_refused` (receiver).

- `EmbeddedDriver::add_network_publication_with_roles` and
  `EmbeddedDriver::add_network_subscription_as` are public: a network
  publication's required `receiver_id`s and receiver tags (`PublicationRoles`),
  and a subscription's receiver identity (`ReceiverIdentity`), owner item 7
  (karyos#637, part 1 of 5).

- Typed roles and receiver identities over the client command path (owner
  item 7; karyos#637, part 2 of 5; layout decided 2026-10-27 by
  QS-COORDINATOR under owner delegation).
  - Two new CnC commands: `AddNetworkPublicationWithRoles` (0x12) and
    `AddNetworkSubscriptionAs` (0x13). The layout is in `karyos_protocol::cnc`.
  - The new error codes are `StrategyConflict` (17) and `InvalidRoles` (18):
    roles longer than the driver's membership holds, or a repeated
    `receiver_id`.
  - Rust client: `ClientConductor::add_network_publication_with_roles`,
    `ClientConductor::add_network_subscription_as`,
    `Client::add_exclusive_publication_with_roles` and
    `Client::add_subscription_as`.
  - C ABI 0.1.2: `karyos_client_add_publication_with_roles`,
    `karyos_client_add_subscription_as` and `KARYOS_STRATEGY_*`, with two
    conformance scenarios. The conformance suite now needs ABI 0.1.2.
  - `PublicationRoles`, `ReceiverIdentity` and `Strategy` move to
    `karyos_protocol::roles`. `karyos_driver::membership`, `karyos_client`
    and the `karyos` facade re-export them.
  - The roles' only size bound is the command ring's largest record
    (`ring_capacity / 8`), which the driver now decodes into a buffer of that
    size, allocated once. A client refuses roles that do not fit
    (`ConductorError::CommandTooLarge`) or are not well formed
    (`ConductorError::InvalidRoles`) before sending.
  - The driver checks a command's required and tagged counts against its
    membership's `max_receivers` before it reads either list, then finds
    repeats by sorting a copy in a stack buffer of that size: O(n log n),
    allocating nothing. The decoder refuses a zero `receiver_id` or tag; a
    repeated `receiver_id`, like a list too long, is `Error` with
    `InvalidRoles`.

- A conflated view of a network image has a public way in, the embedded
  driver's, as IPC views in a process have (owner item 7: "receiver-side
  conflated subscriptions"; karyos#637, part 3 of 5; decided 2026-10-27 by
  QS-COORDINATOR under owner delegation).
  - `EmbeddedDriver::add_network_subscription_conflated` and
    `EmbeddedDriver::recreate_network_view` are public.
  - A view is read with `EmbeddedDriver::subscribe_conflated` on the image's
    lane stream, each value with its freshness.
  - A client of a driver in another process is still refused a `karyos:udp`
    conflated subscription (`ClientError::UnsupportedChannel`): the view's
    table is on its driver's heap, and remote clients are not in scope of the
    design (`conflated-network-images.md`, (c)).

- A network publication's admission state is visible (owner item 7: "the
  existing NotJoined/LostRequired outcome mapping"; karyos#637, part 4 of 5;
  decided 2026-10-27 by QS-COORDINATOR under owner delegation).
  - `NetworkAdmission { Open, NotJoined, LostRequired }`, `#[non_exhaustive]`.
  - Each sender cycle stores it in a slot the conductor reads and in a new
    `network admission` publication cell.
  - The conductor sends a client's network publication a new CnC event,
    `PublicationAdmission` (0xC8, admission `VERSION` 3). It is sent when the
    sender first reports the state, when the state changes between two of the
    conductor's duty cycles, and again before the answer to a `QueryCutover`.
  - A client that laps the broadcast reads the state as unknown until the
    state is sent again: an in-process conductor asks for it, and a remote
    client's lap query already does.
  - Getters: `Client::network_admission` and
    `ClientConductor::network_admission`, `None` until reported;
    `EmbeddedDriver::network_publication_admission`; and the C ABI's
    `karyos_publication_network_admission` with `KARYOS_ADMISSION_*` (ABI
    0.1.2).
  - It is the last state observed, not each transition (the membership
    counters count those). Offers keep the existing mapping: under
    `NotJoined` and `LostRequired` they answer `BackPressured` once the window
    is full, never a terminal outcome. Tested on Linux with one case per cause
    and a change seen by event.

- karyos#622: the first crates.io publication. `karyos-sys`, `karyos-protocol`,
  `karyos-codec`, `karyos-client`, `karyos-io`, `karyos-archive`,
  `karyos-cluster` and the `karyos` facade are published as `0.1.0-alpha.3`;
  each lifts `publish = false` on its own and carries a README, keywords and
  categories. Every other crate stays unpublishable. The repository is public.

- The netem suite isolates each fault (karyos#626). N10 and N11 run
  under reorder alone, with a probe that fails unless the path reordered
  and lost and duplicated nothing: a reliable channel still delivers
  exactly once and in order, and an unreliable one at most once and in
  order, every datagram too late for its place in a reported local gap.
  N3 adds a duplicates-only phase, in which nothing is NAKed or repaired
  and every DATA frame dropped is a duplicate. N4 asserts the repair in
  Dedicated mode through the per-stream cells. `RELEASING.md`: a release
  is not tagged until every gate has an Evidence row for its own head.

- Multi-destination unicast, manual mode, first sends
  (`quantstratum-docs: karyos/design/multi-destination-unicast.md`;
  ADR-0056, ADR-0082; karyos#630, step 1 of 3). A network publication on a
  `control-mode=manual` channel sends every datagram over unicast to each
  listed destination from one endpoint, so fan-out needs no IP multicast.
  Each destination has its own SETUP (announced until its receiver is
  live), SMs and image; answers go only to a listed destination. The
  channel's flow-control strategy and required receivers apply across
  destinations, and each destination is also held at its own window.
  `EmbeddedDriver::add_network_publication_with_destinations` names
  required destinations by endpoint; at most 16 destinations. Until the
  next steps, a destination that stops consuming holds the others,
  retransmissions are not sent, and reliable channels, guards and timed
  lanes with destinations are refused. `control-mode=dynamic` is refused
  with the new `DriverError::DynamicRegistrationUnsupported`.

- Multi-destination unicast, manual mode, step 2 of 3 (karyos#630):
  - A slow optional destination is removed instead of holding the
    others (MD-7): at the first datagram its full queue cannot take while
    the others take it, with no grace, counted in `removed_slow`. It is
    never removed while the publisher is held by a required loss, while
    the shared socket pushes back, or while it bounds the others under
    `min` or inside a `tagged` group. A required destination still bounds
    the publisher.
  - Send faults stay with their destination (MD-12): its queue is retried,
    and after three consecutive faults an optional destination is removed
    (`removed_fault`) and a required one held. A queue that refuses its
    retry is counted (`retries_refused`) and, for a required destination,
    goes to the control path, which resets the endpoint.
  - A removed destination gets nothing more, its EOS included, and no
    longer keeps a lane from idling or draining: the others still get
    their heartbeats and the publication's EOS. One that fails to open on
    a new epoch no longer holds the others.
  - Removals are reported with their reason through
    `EmbeddedDriver::network_removed_destinations`
    (`DestinationRemoval`, `RemovalReason::{Slow, Fault}`). A removed
    destination's SMs and NAKs are ignored, and it no longer counts for the
    strategy edge or the restart position.
  - Reliable channels with destinations are accepted. Each destination has
    its own repair path and repair queue, with a fair share of the job
    table, so a retransmission reaches only the destination that asked
    (MD-8).

- Multi-destination unicast, manual mode, step 3 of 3 (karyos#630):
  - Optional destinations change at run time (MD-3). Use
    `EmbeddedDriver::add_network_destination` and
    `EmbeddedDriver::remove_network_destination`; the sender's answers
    come back through `take_network_destination_changes` as a
    `DestinationChange`.
  - An optional destination moves by a removal and an addition. A removed
    destination is quarantined for `image_liveness_timeout` before it can
    be added again (MD-14).
  - Required destinations are fixed at creation (ADR-0082): one is never
    removed or added at run time. A restart of its receiver at the same
    endpoint is rejected, so the publication's admission is
    `LostRequired`.
  - A NAK has one entry point in the sender's publication, which repairs
    toward the requester's destination on a multi-destination
    publication and on the single path otherwise.
  - A removed destination retires once its queues are drained and its
    removal reported (design 3.7): its queues and route close and its slot
    is freed (`destinations_retired`), so moving an optional destination
    any number of times never fills the table. Its address is kept for its
    quarantine (MD-14); a destination added back is a fresh one, with a
    fresh repair path.
  - Each destination's repair cap is the job table's share for
    `MAX_DESTINATIONS` (MD-8), so additions never overcommit it. A reliable
    multi-destination publication now needs `repair_jobs` of at least 16;
    one configured below, which step 2 took, is refused with
    `RepairConfigError::DestinationShare`.
  - An optional destination whose route or queues cannot open for a reason
    of its own (no route or queue left, an address it cannot route) is
    removed after three tries, at most one per `setup_interval`
    (`RemovalReason::Fault`); an endpoint reset never counts. A change on
    a multi-destination publication being removed answers
    `DestinationChange::Removing`.
  - `network_removed_destinations` keeps the newest 16 removals;
    `network_removals_overwritten` counts the older ones.
  - A removed destination's member stops counting for the strategy edge at
    its removal (design 3.7), not at its liveness expiry, and a sender
    reset asked for in an epoch is no longer cleared before the sender
    acts on it.

- `karyosd --idle-image-timeout <duration>` sets the network agents'
  `idle_image_timeout`, how long stationary heartbeats keep an image alive
  after its last fresh evidence (owner item 1; karyos#638). It takes the
  channel URI's duration grammar (`ns`, `us`, `ms`, `s`), needs
  `--network on` in any order, and a bad duration is the new
  `ArgsError::InvalidDuration` with its `DurationError`. `Options` gains
  `idle_image_timeout`. The default stays 60 s.
- Tests for owner items 13 and 58 (karyos#638): a network publication with a
  local reader and a live receiver stays connected through either, so
  connected never proves remote reachability; and a `Monotonic` lane is
  refused to a client whose time namespace is proven different (two
  distinct namespace files), with that namespace's own code. The namespace
  comparison is now a function of its own, `compare_time_namespaces`, so it
  is tested without privileges. No behaviour changes.

- The two wire additions of dynamic multi-destination registration:
  RSP_SETUP variant 3 REGISTER (56 bytes, the stream and the receiver
  block) and ERR variant 3 REGISTRATION with reason 4 `DESTINATIONS_FULL`
  (40 bytes), as codecs with hand-written vectors (ADR-0056, ADR-0082;
  design MD-4, MD-5; karyos#644, step 1).
- `sessions::register`, the bounded admission of a REGISTER: an explicit
  non-empty `RegistrationAllowlist` (no permissive default; it supplies no
  authentication) per publication; the driver's rate, pending table and
  refusal table shared by its publications, with the sender's
  `setup_answer_rate` as the per-source bucket; pending bounds and one
  ERR per `refusal_interval` per source address, whatever its port;
  checked, sticky counters; and expiry at `join_timeout`. `control-mode=dynamic` stays
  refused until the sender and receiver paths are implemented and tested
  (karyos#644).

- Dynamic multi-destination registration (`control-mode=dynamic`) is
  complete inside the driver (#644, step 3c) and still refused by every
  public publication and subscription call with
  `DriverError::DynamicRegistrationUnsupported`: a review found denial of
  service defects in the registration path, and the refusal stays until
  they are fixed (#644). Inside the driver, a dynamic publication admits
  the receivers that register at its `control` address from a source its
  explicit, never empty `RegistrationAllowlist` names, which restricts
  admission without authenticating anything, and a dynamic subscription
  registers with its configured `ReceiverIdentity`. Challenge and
  response, the driver's registration rates and pending bounds and the
  source checks apply to every registrant, and a full destination table
  answers one ERR REGISTRATION per source per interval.
- Required receiver ids in dynamic mode (MD-17): each has a reserved
  destination slot and two reserved pending registrations (the older one
  replaced), so optional registrants cannot fill the table ahead of it;
  admission opens once every one has joined.
- The registration lookups of the design's step 4: a receiver at its own
  destination is dropped; an optional `receiver_id` back with a new boot
  id replaces its old destination at its first status message
  (`restarted`); the same receiver at a new port moves there once its old
  destination has been quiet for `RegistrationConfig::move_quiet` (50 ms,
  `moved`), and is a `duplicate_receiver` before; a required receiver id
  is never restarted nor moved. A registrant whose receiver goes silent
  for `image_liveness_timeout` loses its slot (`timeout`), and no
  dynamic destination is announced to periodically.
- The registration counters in the CnC: REGISTERs admitted, retried,
  answered ERR or suppressed, dropped by reason, and what registrants'
  first status messages did (joined, full, refused, restarted, moved,
  timed out).

- A `control-mode=dynamic` publication can be built inside the driver
  with its registration allowlist (#644, step 3a): its endpoint binds the
  channel's `control` address and answers a REGISTER from an allowed source
  with one SETUP ANNOUNCE, tested on loopback. A second dynamic
  publication of one stream on one control endpoint is refused with
  `DriverError::DynamicPublicationExists`. The public publication and
  subscription calls still refuse `control-mode=dynamic` until the
  receiver side and its end-to-end tests land.

- A `control-mode=dynamic` subscription can be built inside the driver
  (#644, step 3b): it registers at the channel's `control` address every
  `setup_interval` until an image of its stream from there is bound, and
  counts an ERR REGISTRATION it reads (`ReceiverCounters::registers_sent`,
  `registers_unsent`, `registration_refusals`). Loopback tests show a
  receiver registering, binding and receiving, a receiver outside the
  allowlist getting nothing, and a full table answering ERR while the
  joined destination keeps receiving. The public subscription calls now
  refuse `control-mode=dynamic` with `DriverError::DynamicRegistrationUnsupported`
  (before: `UnsupportedChannel`), as the publication calls do.

- The sender side of dynamic multi-destination registration (#644, step
  2): a REGISTER for a `control-mode=dynamic` publication goes through the
  driver's bounded admission and causes one SETUP ANNOUNCE or one ERR
  REGISTRATION to its validated source; only a pending registrant's
  CHALLENGE is answered, at its source; its first valid SM takes an
  optional destination slot, or gets one ERR REGISTRATION when the slots
  filled meanwhile. A second dynamic publication of one stream on one
  control endpoint is refused. The driver's registration limits are
  `AgentConfig::registration`. `control-mode=dynamic` is still refused at
  channel admission until the receiver side and its end-to-end tests land.

- The channel URI key `retransmit-window=<bytes>` (karyos#653, owner
  item 63) sets a reliable UDP publication's repair window per channel,
  fixed at channel creation. The value must be positive and a multiple
  of 32, and at most half the term; the default is half the term. The URI
  refuses a value that is zero, unaligned, above half of a `term-length`
  it gives, or combined with `reliable=false` (a `Conflict`). The driver
  refuses a value above half of the stream's term with
  `DriverError::RetransmitWindowAboveHalfTerm` before anything is
  configured. Without the key, the driver's `RepairConfig` applies. The
  held floor without required receivers is `sent` minus the window, and
  a test shows that a small window makes the lone counted receiver's
  hole unrecoverable, reported as such. `CHANNEL-URI.md` lists the key.

- `AgentConfig.unicast_retry_slack` (karyos#655): a unicast NAK is
  retried only once its age exceeds the RTT estimate plus this slack.
  The default is 0, which keeps the previous rule; values above 1 s are
  refused (`LossConfigError::UnicastRetrySlack`). The rule cannot
  underflow when the age is below the RTT.
- An early RTT probe: a NAK on a path that has no RTT sample yet moves
  that path's next probe ahead of `rtt_probe_interval`, once per path
  binding generation and never once per NAK; a sampled path, or one
  whose probe is still on its way, is left alone. `RttCounts.early_probes`
  counts them.

- `karyos-feed` A/B arbitration (`quantstratum-docs:
  karyos/design/feed-arbitration.md`; SPEC §7.2; karyos#659). An `Arbiter`
  over a feed's `FeedSequencer` (epoch, sequence, modulus, epoch start)
  delivers each sequenced message of lines A and B once, in order, from the
  line that brought it first. A message missing on one line is repaired
  from the other; one missing on both is a `Gap` once both lines passed it,
  its skew window expired or the reorder buffer overflowed. A session reset
  is an epoch change the feed states; a wrap is serial arithmetic inside a
  window strictly below half the space, and a message at or beyond it is a
  `Jump`. At a reset the old epoch stays open until both lines report the
  new one or the skew window expires, so the lagging line can still repair
  it; the new epoch's messages wait under their own base, and old epoch
  messages after the close are dropped. `resync` resumes a snapshot's
  consumer after a stated position. Named counters cover wins, duplicates,
  late copies, length conflicts and the rest. The reorder buffer is
  allocated at construction: a steady cycle allocates nothing.

- The `ClusteredService` delivery path in the harness (C10; karyos#686,
  part 2 of 5). `karyos_sim::harness::delivery`: `DeliveryServer` runs
  any `ConsensusCore` over C4's log and feeds its committed entries to a
  `ServiceContainer`, proposing through `Proposer`, the core's `Propose`.
  `DeliveryClient` registers, then sends its commands under its epoch
  and sequence. `tests/delivery.rs`:
  - requests reach the log and their outcomes return on 3 and 5
    servers, with every replica in the same state and sessions;
  - a request sent twice is applied once;
  - a restarted server rebuilds its container from the log.

  `ServerNode` and `TestService`, which the frozen C5 workloads measure,
  are unchanged. The reference core now stamps its entries with its last
  tick time instead of 0. This changes the event time only, which
  `TestService` ignores, so no measured behaviour changes; a test checks
  it.

- Leader following and unknown outcomes on the delivery path (C10;
  karyos#686, part 3 of 5).
  - A follower forwards a client's registration or request, one hop, to
    the leader its core names, and relays the answer. The client's
    epoch and sequence are unchanged, so a forward and a retry are
    deduplicated as one request.
  - A server whose core stops leading, or changes term, answers the
    requests it took `Answer::Unknown`, never a failure. The client
    retries the same epoch and sequence, and reports `Unknown` only at
    its deadline.
  - Tests on 3 and 5 servers, over the seed corpus: a forwarded
    request; a deposed leader with a request pending; a leader change
    with a forward in flight; and a deadline. Each command runs once.

- The Cluster's service container, core neutral (SPEC §9, C10;
  karyos#686, part 1 of 5). `karyos_cluster::service::ClusteredService`
  is the user's state machine: `on_command`, `on_timer` and
  `on_configuration`, each seeing only a `Context` of the entry's index,
  term and log time, with timers scheduled and cancelled through it.
  `ServiceContainer` applies committed entries in order. Requests go
  through C7a's `SessionTable`, so a retry gets its retained reply and the
  command runs once. Timer firings and configuration changes are entries,
  delivered only when applied, and a firing proposed twice delivers once;
  `ServiceContainer::due` lists the firings a leader proposes. Entries are
  a versioned `Envelope`, version 1, not frozen. `Propose` is the core
  boundary a core's adapter implements. `SessionTable::observe` moves the
  log time for an entry that holds no session operation.

- Timers and configuration changes through the log on the delivery
  path (C10; karyos#686, part 4 of 5).
  - A `DeliveryServer` that leads proposes `TimerFired` for every
    scheduled timer that is due, and a new leadership proposes them all
    again. A firing applied twice delivers once.
  - `with_configurations` delivers a core's own configuration entries to
    the service as changes, instead of stopping the container.
    `Delivery::Change` takes an operator's membership change.
  - Tests on 3 and 5 servers: a timer fires at its own entry on every
    replica, after the request that set it; a configuration change is
    delivered at its entry; a restored leader proposes due timers again,
    and each fires once.

  `AppendService` now does nothing for a command it does not know,
  instead of reporting a reply too large.

- The C5 harness declares W2's limits to the core under test
  (karyos#687). `ConsensusCore::recover_with` takes `Limits`: in-flight
  entries and bytes per follower, a request queue per server, and log
  bytes read per duty. A core that takes none answers `Unsupported`, and
  its W2 cases are reported as `not_demonstrated`, never as passed.
  `propose` refuses with `Refused::NotLeader` or a typed
  `Refused::Backpressure(Limit)`; each backpressure refusal is recorded,
  and the client sends again, so nothing is lost. The harness holds a
  core's log reads to its per-duty budget (`ReadError::Budget`). W2 runs
  its nominal case, bursts at 4x the queue and the in-flight entries
  from pipelined clients (`Case::window`, each open request a session of
  its own; a client told `Busy` waits its retry interval), a follower cut
  off while the leader commits 10,000 entries, and one 4x the log-read
  limit behind. At 256 B the in-flight byte limit is never reached: every
  W2 run record states it, and the report scores it not demonstrated. The reference fixture honours every limit, as
  harness validation. A metered read is sized from the log's index (`RaftLog::frame_span`,
  new in karyos-cluster): a duty reads only whole frames that fit its
  budget, and a refused read reads nothing. W2 holds every up server to
  the same applied index and state, and every raw result line states its
  client window and what the case does not cover.

- W5's retries in the C5 harness (karyos#687):
  - a leadership handover in the core interface, `transfer_leadership`, whose `Unsupported` default is scored not demonstrated;
  - `Action::TransferLeadership`;
  - a server answers a client sent to a former leader with a redirect to the new one;
  - the test service keeps each client's last 10,000 answers and answers an older retry `Expired`, explicitly, without applying it again.

  The reference fixture hands over to a caught-up voter, which leads the next term. W5 adds the lost reply, leader change and retry case.

- `RaftLog::install` in karyos-cluster restarts a follower's log after a
  snapshot its snapshot store already holds verified (karyos#687, decided
  2026-10-30 by QS-COORDINATOR). Durable on return, in this order:
  1. the first-index file names the next index and the base term in one
     record;
  2. the watermark is cleared;
  3. every frame is cut;
  4. the commit becomes the base.

  `RaftLog::open_with` opens such a log only over its verified snapshot,
  and finishes an install a crash cut short. `RaftLog::open` refuses it
  with `LogError::InstallUnverified`. `RaftLog::frame_span` gives a
  frame's length from the in-memory index.
- The C5 harness's W5 snapshot half (karyos#687):
  - snapshot hooks in the core interface: `compacted`, `install` and
    `Ready::snapshot_to`, with `Unsupported` defaults scored not
    demonstrated;
  - per-server compaction every N applied entries, keeping K;
  - snapshot sends and installs, and recovery from the latest snapshot
    and the log;
  - `W5Snapshots`, which runs compaction under load, a follower held
    behind the compaction point, and crashes around an install and
    between builds.

  A case whose entries cannot fit one duty's log-read budget is refused
  before it runs.

- karyos-sim's C5 corpus runner (part of karyos#691;
  quantstratum-docs: karyos/evaluations/c5-raft-comparison-v1.md,
  Corpora). `harness::corpus::run_corpus` runs every case of the given
  workloads, of one `ConsensusCore`, over a range of seeds, and writes one
  JSON line of raw results per run, with a `Summary`. A line holds:
  - the evidence;
  - the core, workload, case and seed;
  - the verdict (`pass`, `liveness_gap`, a failed check's kind, or
    `error`);
  - whether the run ended at its step bound with clients waiting;
  - the fault schedule, the trace digest, and any error.

  With `repetitions` above 1 it is the determinism gate's mode: each
  seed's run is repeated, and an outcome that differs fails it as
  `failed_not_replayed`.

  Every line of a run of the `Reference` fixture says "harness validation,
  not C5 evidence" in its `evidence` field: no candidate is behind
  `ConsensusCore` yet (#678, #690), so the runner validates the harness
  only. `tests/corpus.rs` runs the manifest's CI seeds (1 to 1,000) over
  W1, W3, W4 and W6, ignored by default, and prints the time and size.
  Per-fault coverage and minimised traces of failing seeds are a later
  step.
- The C5 allocation gate's probe (part of karyos#691).
  - `karyos_sys::alloc_count` counts a set of threads: a thread enrolls
    (`enroll`) and `window` sums every enrolled thread's allocations and
    frees while it runs, for a path that spans an executor's tasks or a
    background thread.
  - `karyos_sim::harness::probe::Probed<C>` wraps a core so that each of
    its calls, once it has committed `WARMUP` (16) entries, is counted.
  - `measure` reports the allocations and frees per entry the leaders
    committed past the warm-up.
  - The declared path is every `ConsensusCore` call plus any thread the
    adapter declares in the run record.
  - `tests/allocation.rs` checks the probe: a known allocation counts, a
    no-op and an unenrolled thread count nothing, and a declared second
    thread counts. It also measures the `Reference` fixture on W1 (about
    62 allocations per entry: it is no candidate, and the line says
    "harness validation, not C5 evidence").

- The binding conformance suite runs its panic row (karyos#699). A
  libkaryos built for the test kit (karyos-ffi feature `test-hooks`)
  exports `karyos_test_panic_next_duty_cycle`, declared in
  `include/karyos_test_hooks.h` and never in `karyos.h`, and the new
  scenario `op.panic.poisons` (feature `fault-hook`) shows a panic on a
  driver's thread poisoning the driver, its client and that client's
  subscription and publication while a second driver and its objects
  still work, and a panic inside a caller's own `karyos_driver_do_work`
  answering `KARYOS_E_INTERNAL` instead of unwinding. `make test-hooks-absent-check`, part of pre-push,
  fails when the release library exports the hook or carries its code.
  `conformance/index.txt` rows are now scenario ids, `pending issue <N>`
  with a reason, or `outside` with a reason for a row no portable runner
  can reach; a `pending` row that names no issue is refused. The kept
  fragment pointer row is `outside`, naming its Rust test, and the older
  minor ABI row is pending on issue 700. FORMAT.md says that a
  scenario's row comes from its `covers` header, never its `feature`
  headers.

- The release tooling of libkaryos as its own artifact, separate from
  karyosd (owner item 44, karyos#700): `scripts/release-libkaryos.sh`
  builds the library package and the karyosd artifact as two tarballs
  with `SHA256SUMS`, deterministic on a host whatever its TZ and umask
  (`scripts/check-release-reproducible.sh`); `scripts/sign-release.sh`
  signs exactly what `SHA256SUMS` lists with key-based cosign and a
  `pkcs11:` key only (no key exists yet, so it refuses); `scripts/conformance-package.sh`
  runs the conformance suite against a released tarball rather than the
  build tree. The package's MANIFEST says `contents=library` and
  `excludes=karyosd`; the conformance test kit says it is not a release
  package.
- The ABI manifest of the C header (`scripts/abi-manifest.sh`): every
  public struct's size, alignment and field offsets and every constant,
  measured by compiling the header, and every other declaration as
  written. It ships as `share/karyos/abi-manifest.txt`, and
  `make abi-manifest-check`, in pre-push, fails a header that no longer
  matches it, or a change since the last released manifest
  (`crates/karyos-ffi/abi/released/`) without a higher ABI version.
- The soname policy is owner item 48's ruling (`0.y` before 1.0), no
  longer an interim note.

- Trace record layout version 4 for application trace points (R-CORE-1,
  karyos#722, first part): point code 9, `Point::Application { id,
  metadata }`, with up to four typed metadata values (`u64`, `i64`,
  `f64`, an 8-byte ASCII tag) in words 16 to 21, refused when out of
  bounds on encode, before a sequence is taken, and on decode. Only
  application records are written as version 4; driver points keep
  version 3, so a layout 3 reader decodes them and refuses the
  application records typed. `ApplicationPoint::observe` records into a
  journal of the point's own client (`TraceWriter::for_client`) and
  refuses another's with `TraceError::ForeignPoint`; it allocates
  nothing, nor does a driver point's record with no point registered.

- The agent's `trace-export` names application trace points (R-CORE-1,
  karyos#722, last part): each page carries `points`, one
  `{"id","label","client"}` per point its records reference, its label
  escaped as every string. A point is named only by the single live
  trace point cell holding its id, of the client of the journals its
  records are in; otherwise its label and client are `null`, never
  another point's. A point counts once in the reply's byte bound, at
  384 bytes. `limits` gains `trace.point_ids` (65 535),
  `trace.points_per_client` (16) and
  `trace.point_registrations_per_client` (256), all fixed.

- Application trace point names (R-CORE-1, karyos#722, second part):
  `Client::add_trace_point(label)` registers a point as a client counter
  cell of type id 8 (`TYPE_TRACE_POINT`), whose value is the id the
  driver assigns and publishes with the cell, never reused within the
  instance. Labels are checked by the client and again by the driver
  (1 to 64 bytes, no control character; `ClientError::InvalidLabel`,
  `ErrorCode::InvalidLabel` 27). A client holds at most
  `max_trace_points_per_client` live points (16) and registers at most
  `max_trace_point_registrations_per_client` over its life (256), with
  `karyosd` flags of the same names; once the instance assigned all
  65 535 ids, a registration is refused with
  `ErrorCode::TracePointIdsExhausted` (26) and counted in the driver's
  `trace point ids exhausted`. The agent's Prometheus exposition and
  `karyos-stat` leave trace point cells out: they name records and hold
  an id.

- R-CORE-3, application counters (karyos#723). `Client::add_counter(label,
  CounterKind)` registers a named counter of the driver's client counters
  region, keyed to the client and to no stream: `CounterKind::Event` (type
  id 6, `TYPE_APPLICATION_EVENT`) or `CounterKind::Gauge` (type id 7,
  `TYPE_APPLICATION_GAUGE`). The bound is the driver's
  `max_counters_per_client`, shared with the client's other counters, and
  past it registration is refused with `ClientError::Refused`
  (`ResourcesUnavailable`); a label of more than 64 bytes is refused, never
  truncated, and a second live counter of the same label and kind with
  `ClientError::DuplicateCounter`, so the export never repeats a series. The cells are freed when the handle is released or the client
  goes. The agent's exporter shows them as `karyos_application_events_total`
  and `karyos_application_gauge`, labelled with the name and the client, and
  `karyos-stat` lists them under "application counters:". Updating one
  allocates nothing.

- Raw trace export (R-CORE-13, karyos#724). The new API v1 request
  `KARYOS-AGENT 1 trace-export DIR FROM [COUNT [EPOCH]]` returns pages of
  the attached driver's trace mirror records, read from the mirror at the
  call: whole records in mirror sequence order, `next` to resume from,
  the ring's `head`, and the journals the records name as the table showed
  them (entry with clock provenance, time namespace and drop ranges;
  recycle log entry; or unknown). The epoch is the driver instance (32 hex
  digits): a cursor survives the collector's and the agent's restart, and
  one of another instance gets the typed `epoch changed` refusal with the
  new epoch. A cursor behind retention, or a record overwritten during the
  read, is never refused or delivered torn: the page states the lost
  sequences first, in `lost`. At most 16 384 records per request (default
  1024). A reply holds whole records, each counted with its journal the
  first time one names it, within 1 MiB plus one record and one journal
  (`MAX_RECORD_REPLY`, 695 bytes; `MAX_JOURNAL_REPLY`, 2560 bytes), the
  read itself bounded by those bytes and the count clamped to 16 384; it
  names only the journals of the records it holds. A cursor beyond the
  ring is refused (`cursor ahead`, with the ring's `next`), as is a read
  that finds the ring's bounds busy (`mirror busy`); the head is always
  the ring's. A record whose journal entry stays busy ends the page
  before it (the reader retries); a journal recycled for good goes out as
  `unknown`, its records counted in `unknown_records`. A malformed record
  (a length past the payload bound, `MirrorRecord::truncated`) is never
  delivered: it is lost with its sequence and reason `malformed`, and the
  page goes on. A table or log entry being written is retried, yielding,
  for 1 ms, the table's before the log is read, as the driver writes a
  log entry before it reuses a table entry; one still busy then, while a
  page's first record is its journal's, never stalls the cursor and loses
  nothing: that journal's leading run of records goes out without
  calibration, its journal `unreadable`, counted in `unreadable_records`,
  and the page ends at the next record whose journal was not read. Each lost range carries its `reason`
  (`overwritten` or `malformed`), is stated once, and is below the page's
  `next`. The read alone bounds the page, in
  batches of 64 records; `json::trace_export` encodes it whole.
  `capabilities` lists `trace-export`.
- `karyos_sys::diag_ring::scan_at_most` and
  `TraceMirrorReader::scan_at_most`: a ring scan that delivers at most a
  given number of records, so its work is bounded by that number.
- `trace-buckets` paging (R-CORE-23, review of karyos#817): a bucket's
  `loss` is on its first page only (`first_lane` 0) and `null` on a later
  page of it, so a reader never counts it twice; no page holds a bucket's
  header without a lane.
- The API socket writes each reply within `WRITE_DEADLINE` (250 ms) in
  all, checked after every write: a reply a client reads too slowly is
  cut short, and the connection closed, so it ends at EOF without its
  final newline; a reply written whole is served even if its last write
  ended at the deadline. `limits` answers it as `write.deadline_ms`. A
  request is read within `READ_DEADLINE` (250 ms) in all, each read under
  the time left (`read.deadline_ms`). One poll
  starts connections for `POLL_BUDGET` (500 ms) at most, so its waiting on
  clients is 1 s at most, besides the work of building the answers. Refusals of
  `trace-export` are served as refusals.

- Disjoint trace buckets (R-CORE-23, karyos#727). The agent's trace window
  keeps each closed slice as a bucket that shares no pair with any other,
  sparse, under `WindowConfig::max_bucket_bytes` (default 64 MiB of
  structs and allocations at their capacity, oldest evicted first; a
  bucket larger than the budget is not kept). The new API v1 request
  `KARYOS-AGENT 1 trace-buckets DIR FROM [COUNT [EPOCH [LANE]]]` returns
  them with the window run's `epoch`, each lane as mergeable counts and
  each bucket's loss (the scan's loss charged to the bucket missing the
  pairs, malformed and unknown-journal records included); reading
  consumes nothing, so any number of readers share them. Refusals are
  typed: `epoch changed`, `buckets expired` (any number below the oldest
  answered, never an empty bucket in its place), `bucket over budget`. A
  reply holds whole lanes within 1 MiB plus one lane (at most
  `MAX_LANE_REPLY`, 2 870 932 bytes): a larger bucket is paged by lane,
  and `next` names the bucket and the lane where the next read starts. `capabilities` lists
  `trace-buckets`; the view's trace counts add `buckets_evicted` and
  `buckets_over_budget`. The rolling `trace-window` view is unchanged.
- `karyos_trace::Histogram::counts` and `Histogram::from_counts`
  (`HistogramCounts`, `SideCounts`): a histogram's counts exported and
  rebuilt exactly, refusing another layout or unit (`Mismatch`) and
  inconsistent counts (`InvalidCounts`).

- R-CORE-24, the management agent's identity, attachment and capability
  discovery (karyos#728), all additions to API v1:
  - `karyos-agent --agent-id NAME` names the agent, as its deployment
    calls it (for example `namespace/pod`). It is taken from configuration
    only; the agent looks up no host or orchestrator name.
  - The view gains `agent`: `id`, `pid` and `started_ns`. The pair (pid,
    started_ns) identifies the agent's incarnation; `started_ns` is host
    `CLOCK_MONOTONIC`, not a wall-clock time.
  - Each driver gains `attachment`: `since_ns`, `attaches`, and `previous`,
    the end of the last attach (its instance, `ended_ns`, and
    `driver_gone` or `detached`).
  - New request `KARYOS-AGENT 1 capabilities`, answered for the caller's
    role. Each capability of a closed v1 list (`view`, `guard-close`,
    `guard-reopen`, `gap-ack`, `catalog`, `trace-window`, `limits`) is
    `served`,
    `unavailable` (off in this deployment: `not_configured` or
    `journal_unavailable`) or `forbidden` (`role`).
  - The request with arguments answers
    `{"error":"bad arguments","request":"capabilities"}`. An older agent
    answers `bad request`, which a client reads as no discovery.

- `--versions` on every binary of `karyos-tools` (R-CORE-33, karyos#729):
  one JSON object with its own schema (`karyos-versions`, version 1),
  printed before anything else is parsed and touching no driver. It has
  the core release, the admission and frame protocol versions, the C ABI
  version, the wire schema versions (Archive control, Cluster log, group
  records, capture contract, Archive durability), the `karyosd`
  configuration file schema version (`config::SCHEMA_VERSION`, 1 = the
  `[io]` schema), the backends the core knows (sockets, io_uring, af_xdp,
  ef_vi, dpdk) with whether this build compiled them, and the enabled features,
  each with the id of the rule it is compared under. The C ABI version
  now has one source, `karyos_protocol::versions`, which `karyos-ffi` and
  its header follow. A `libkaryos` package carries the same object as
  `share/karyos/versions.json`, checked against its MANIFEST.

- R-CORE-34, the size of every shared region from its configuration
  (karyos#730, first part). These are the functions each region's
  constructor now uses, so they cannot drift from the size it is mapped
  with:
  - `karyos_sys::sizing::region_length`, the header stride plus the
    structure, used by `RegionRecord`;
  - `command_ring::structure_length` and `broadcast::structure_length`;
  - `counters::structure_length`, for the counters and the client
    counters;
  - `diag::{error_log, loss_report, guard_audit}_structure_length`;
  - `trace_mirror::structure_length`;
  - `LogBuffer::structure_length`.

  A Linux test creates every region kind and compares its record and its
  `memfd` size with them.

- R-CORE-34, the sizing report (karyos#730). `karyos_driver::sizing::report`
  (Linux) computes, from a driver configuration and its streams alone, the
  bytes of every shared region the driver and its clients map, each
  rounded up to the page (`karyos_sys::ipc::page_size`), in two figures:
  - configured steady state: the regions, plus the network trace journal
    budget, listed apart as heap;
  - restart peak: configured plus `max_retained_generations` predecessor
    mappings of every declared stream, under a stated assumption (no
    reconfiguration since start).

  Streams added after start and Archive replay targets are excluded, and
  the report says why: no configuration sets their maximum geometry.
  Every line names the configuration fields it read. The report states how
  the cgroup counts a shared `memfd` page and what it excludes, and it
  refuses whatever the driver refuses.
- `DriverConfig::validate`, the check a driver applies when it is created,
  now public and shared with the sizing report.
- `karyosd --sizing-report` prints that report for the other options,
  including the Archive's two control streams with `--archive`, and exits
  without starting a driver; `--dir` is not needed.

  A Linux test compares the report with the regions a driver maps, read
  from `/proc/self/maps`, to the byte, with a conflated stream and the
  network on. Another keeps a running `karyosd`'s region pages within the
  configured figure, and its resident set within that figure plus 10 % and
  4 MiB.

- R-CORE-35, a bounded startup and readiness signal for a driver
  (karyos#731).
  - `EmbeddedDriver::readiness` reports one of five states: starting,
    ready, recovering (a stream retains a cutover's predecessor), not
    ready (orderly shutdown, full or terminal) or failed (startup
    deadline). It is derived from the conditions a client `Hello` is
    admitted under.
  - `EmbeddedDriver::startup_complete` and `DriverConfig::startup_timeout`
    (30 s) bound startup. A host that never declares its startup complete
    reports failed. `karyosd` declares it once its streams and Archive
    exist.
  - The admission protocol (version 3) gains `ProbeHello` and `ProbeState`.
    A probe gets no descriptor or slot, does not count against
    `max_clients` or `max_tools`, and one step answers at most
    `MAX_PROBES_PER_STEP` (4) probes.
  - Linux: `karyos_client::probe::probe` and `karyos-tools probe --dir D`.
    The command exits 0 ready, 1 starting or recovering, 2 not ready or
    failed, 3 unreachable, 4 incompatible driver and 5 refused.

- The wire compatibility matrix (R-CORE-36, karyos#732):
  `crates/karyos-tools/compat/matrix.toml`, indexed by the full versions
  tuple of `--versions`, not by the frame version alone, with one entry
  per ordered pair of builds and surface (admission, frame, C ABI, the
  Archive and Cluster schemas, the configuration file): interoperate,
  refuse with its typed reason, or not covered with why.
  `karyos-tools compat <FROM> <TO>` decides a pair from two `--versions`
  objects or named columns (exit 0 interoperate, 1 refuse, 2 not covered,
  3 an unreadable input), through a strict, bounded reader of the
  `karyos-versions` schema. `scripts/compat-test.sh` is the local release
  gate that runs a released tag's and this tree's builds against each
  other in Linux and compares every outcome with the matrix: 0.1.0-alpha.2
  and main refuse each other's clients at admission and interoperate
  over karyos:udp.

- The metrics exporter's capabilities for its first release (R-CORE-39,
  karyos#734).
  - **Attachment:** `karyos_exporter_info{id,pid}` and
    `karyos_exporter_started_ns` give its identity as an agent's
    (`--agent-id`, as `karyos-agent` has). Per driver,
    `karyos_driver_up`, `karyos_driver_state{state}`,
    `karyos_driver_info{instance}`, `karyos_driver_attaches_total` and
    `karyos_driver_attached_since_ns`. A driver that is not attached is
    reported as a state: no alert count, no counters and no last values,
    so a dashboard never reads zeros as healthy.
  - **Security:** still loopback only, now refused with a message that
    points to a TLS-terminating sidecar or mesh. An optional
    `--token-file` (mode 0600, 32 to 256 bytes) makes every scrape carry
    `Authorization: Bearer`, compared in constant time. A request without
    the token, or with another, is answered `401` with a `Bearer`
    challenge, and a malformed request head `400`.
  - **Metric families:** `exporter::FAMILIES` lists each family with its
    type and stability, and a test keeps the exposition to it. The
    per-cell families keyed by a driver's internal counter label are
    unstable.
  - No OTLP.

- An embedded driver's network over the C ABI (karyos#735), ABI 0.1.4.
  - `karyos_driver_options` gains `network` (`KARYOS_NETWORK_OFF` 0 or
    `KARYOS_NETWORK_ON` 1) and `reserved0`.
  - ON runs the driver's network agents with their default configuration,
    on their own threads, so its clients create `karyos:udp` publications
    and subscriptions with the existing calls.
  - An older caller's struct, and OFF, keep the IPC-only driver.
  - Any other value, or a nonzero `reserved0`, is
    `KARYOS_E_INVALID_ARGUMENT`, with nothing created.
  - Only on and off are exposed. The rest of the network configuration
    keeps its defaults, as with `karyosd --network on`, and the header
    lists it.
- The conformance suite adds the feature `embedded-network`, with
  `driver.create_networked` and `$network_uri`, and the scenario
  `op.embedded.network`. The suite still needs ABI 0.1.3; the feature
  alone needs 0.1.4, and a 0.1.3 binding declares it absent.

- The agent keeps a join metadata registry (karyos#736; Insights
  ADR-0022: "Versioned metadata joins through a public, agent-visible
  registry serve stable dimensions"). A product with the new role
  `registrar` (or an administrator) puts versioned `name=value`
  attributes about a driver's stream id, application trace point label or
  application counter label with `join-put DIR KIND KEY NAME=VALUE...`,
  and ends one with `join-retire`; any role reads the version in force at
  an instant with `join-get DIR KIND KEY [AT_NS]` and pages them with
  `join-list DIR [KIND KEY]`. Each version is valid from the agent's host
  monotonic time of its put to the next put or the retire. Bounded, each
  bound in `limits` (`join.*`) with a typed refusal: 1024 keys in all and
  per driver, 4 versions per key, 16 attributes, 32-byte names, 64-byte
  values, a 1024-byte `join-put` line, and a computed worst case of
  6.5 MiB (`join.memory_bytes`). In memory only, with a
  `generation` per agent start. A read gives what the agent observes of
  the identity now: whether a trace point or application counter of that
  label exists and how many clients hold it; for a stream, `null`, as no
  driver cell carries a wire stream id. The `view` is unchanged; the
  `capabilities` list gains `join-registry` and `join-put`.

- Per-datum identity and sample time in the agent's data (R-CORE-17;
  karyos#737). API v1 gains fields only.
  - Each counter now carries `cell_registration`, `read_ns` (when the
    agent read it) and `changed_ns`. `changed_ns` is the first pass in
    which the agent saw the value change: an upper bound on the change,
    which happened after the previous pass's `read_ns`. It is `null`
    until a change has been seen.
  - Each lane carries `sampled_ns`, the driver's sampling time of its
    positions. Each subscriber carries `cell_registration` and
    `changed_ns`, stamped with the agent's read in a pass that is not
    consistent.
  - A datum's identity is the driver instance plus its
    `cell_registration`, which a region never reuses. A reallocation
    under the same keys is a new series, and a new instance breaks
    every join.
  - The agent tracks changes by registration, in region order, with an
    index for the cells that churned. A freed counter leaves no entry,
    the tracking allocates nothing in a steady state, and a pass costs
    O(cells).
  - `consistent`, `sampled` and `age_ns` are unchanged.

- Rate policy versions and run-time changes (R-CORE-21, karyos#740):
  - `EmbeddedDriver::change_rate_policy` and
    `change_aggregate_rate_policy` change a guarded stream's rate policy
    by version (compare and set). `RateAuthority::Safety` takes only a
    provable tightening (`RatePolicy::transition`); `Administrator` takes
    any valid policy. No policy goes below the stream's control reserve,
    in messages and, for a byte limit, in reserve messages of the largest
    frame (each reserved message counted as a full frame). A change on one
    lane of an aggregate of several lanes is a change of the aggregate:
    its guarded lanes take it together or not at all, and each guard
    audits it. The version, the transition and the policy's validity are
    the publication's; each lane is weighed only against its own reserve,
    and a lane whose reserve the policy would cross is
    `DriverError::RateChangeOnLane` with `ReserveCrossed`, naming the lane
    (`LaneRefusal::Change`), with the refusal's own CnC code. A publication has one
    policy and one version, kept by the driver for its aggregate: a lane
    guarded with no rate takes it, one guarded with the same policy joins
    at its version, and one guarded with another policy is refused and
    audited (`DriverError::RatePolicyConflict`, with both, code 25): only
    a change changes it. The first lane guarded with a rate gives the
    policy, at version 1, to the lanes guarded before without one, each
    audited from no rate (version 0).
    A handle with no copy (a rateless lane's, a remote one's before a
    policy) watches its ring's slot and takes a policy published later
    at its next call, its copy starting empty; the gate's slot is published with it. A lane guarded
    without a rate on a publication with a policy is audited from no rate
    to its version. A publication's stored policy goes with its last lane.
    A retiring lane, guarded or not, refuses a change as retiring.
    Unguarded lanes are left as they are. Refusals are `DriverError::RateChange` (`VersionMismatch`,
    `NotATightening`, `ReserveCrossed`, `NoRate`) and
    `DriverError::InvalidRatePolicy`, with CnC error codes 19 to 23 (23
    `RateInvalidPolicy`) and 25 (`RatePolicyConflict`). A byte burst is validated against the largest
    lane MTU.
  - A change binds at once and never grants tokens: each bucket earns the
    old rates up to the change, then its level is clamped to the new
    burst (`RateLimiter::set_policy`). A byte limit added starts empty.
  - The driver publishes the policy in each bound handle's outcome ring
    (header words 6 to 12, reserved and zero in layout version 2, so no
    version change) and in the sender gate's slot
    (`karyos_sys::rate_policy_slot`, a sequence lock with a Loom model).
    A handle's copy compares the slot's sequence word on every call (one
    Acquire load) and applies a newer version before it answers; a network
    sender gate at each serve. A handle in another process now takes its
    rate copy from its ring when it binds (before, only an in-process
    handle had one), or at its first call that reads the slot whole when a
    publication was in progress at bind. A reincarnation publishes nothing
    to the gate's slot, and an aggregate's change publishes it once.
  - Every call that names a guarded stream, accepted or refused, is in
    the guard audit: outcome `RateChanged` (ring code 5), or
    `RateUnchanged` (ring code 6) for the policy in force, `before` and
    `after` the policy versions, `parameters` the authority.

- The `karyos` facade publishes its versions (R-CORE-33, karyos#752):
  `karyos::CORE_VERSION`, the core release it was built from, and
  `karyos::PROTOCOL_VERSION`, the admission protocol version its client
  announces (defined in `karyos-client`, asserted equal to the protocol's
  at compile time). They are the values the C ABI and a `libkaryos`
  package's manifest publish, readable without the C ABI, as the Python
  binding needs.

- A configuration file for `karyosd` (R-CORE-43, karyos#769):
  `--config <path>` reads the `[io]` table of SPEC 16.9 (TOML).
  `backend` selects the I/O backend (default `sockets`) and `require`
  the capabilities every endpoint must have active: one that lacks a
  required capability fails to open, at startup or at the first add
  that opens it.
  `[io.sockets]` sets `tx_slots`, `max_queues` and `max_routes` of each
  endpoint. `--io-backend` and `--io-require` override the file; the io
  configuration needs `--network on`.
- A backend this build does not have is refused with a typed error and
  never replaced: `io_uring` and `af_xdp` are not built,
  `ef_vi` and `dpdk` need `karyosd-native`. Any other key, table or
  name is refused by name; a table error names its key or its line.
- `karyos_tools::config`, the extension point: a backend implements
  `IoBackend` and registers in an `IoSchema`, which parses and
  validates its `[io.<name>]` table; `args::parse_with` takes the
  schema and `Options::io` gives the table back. It re-exports `serde`
  and `toml`, so a major version of either is a breaking change of
  `karyos-tools`. Running another backend waits on R-CORE-27.
- `NetworkConfig::require`: the capabilities every endpoint the driver
  opens must have active.

- The optional borrowed-term TX operation (karyos#771, R-CORE-45 part
  2). `TxBackend::submit_borrowed` queues the frames of a `ReadLease` as
  one datagram. Its default stages: it claims a frame, copies the lease
  into it byte for byte as a copy read gives, commits it, and ends the
  lease. The sockets backend, and every backend that does not borrow,
  behaves as before. A refusal hands the lease back, still held, with a
  typed `BorrowError`. A backend that borrows keeps its leases in a
  `LeaseLedger`, allocated at creation for the sender's bound
  (`LeaseLedger::new` reserves fallibly and refuses 0 or an impossible
  capacity, typed `LedgerError`). A lease is released only when a
  completion or a returned item proves the bytes are no longer
  referenced. A reset (`begin_reset`) waits for every lease and past the
  retirement bound reports `ResetDrain::Stuck`, counted once, keeping
  the leases so their terms stay pinned. Leasing, staging and the
  ledger's hold and release allocate nothing.

- Read leases on committed term bytes (karyos#771, R-CORE-45 part 1).
  `LogBuffer::install_leases` installs a bounded bank of lease words, on
  the creating process's buffer only (an attached one is refused,
  `SysError::LeasesNotOnAttached`). `SenderRead::lease_committed`
  validates the frames a copy would carry and leaves them in the term
  under a `ReadLease` instead of copying them. While a lease lives,
  reclaim keeps its slot quarantined, so the term is never cleaned or
  reused under it, across any rotation. Dropping the lease ends it with
  one `Release` store, from any thread, with no lock and no allocation.
  `ReadLease::copy_to` stages a lease byte for byte as `read_committed`
  copies. A full bank, a padding or aborted record at the cursor, or a
  reader that borrows its buffer (`&LogBuffer`) stages
  (`LeaseOutcome::Stage`), with the cursor unmoved. `ReadLease` names no
  buffer type: it holds its `Arc`-owned buffer as a trait object, with
  no allocation, so a backend can keep leases of any buffer. `TermBytes`
  is now `'static`. New counters: `leases`, `lease_bytes`,
  `leases_staged`. The `loom_read_lease` models check that cleaning
  never races a lease released on another thread, with a second lease
  taken concurrently on the same term.

- R-CORE-35 over the C ABI (karyos#794), ABI 0.1.3:
  - `karyos_driver_startup_complete(driver, *complete)` declares the host's
    startup complete. It writes 1, or 0 when `startup_timeout_ns` had
    already passed.
  - `karyos_driver_readiness(driver, *out)` writes a `karyos_readiness`:
    the state (`KARYOS_READINESS_STARTING`, `_READY`, `_RECOVERING`,
    `_NOT_READY`, `_FAILED`), the reason (`KARYOS_READINESS_REASON_*`),
    and the uptime. The values are those of the admission protocol's
    readiness probe. A `size` below 24 bytes is
    `KARYOS_E_INVALID_ARGUMENT`; a larger one gets the fields this version
    knows.
  - `karyos_driver_options` gains `startup_timeout_ns`. Its default is 30 s,
    and an older caller's struct gets that default; 0 is refused.
  - Both calls work with or without `karyos_driver_start`.
- `EmbeddedDriver::uptime` is public on every platform, and
  `Readiness::wire` gives the probe's state and reason codes. The admission
  server's probe answer and the C ABI share them.
- The conformance suite needs ABI 0.1.3. It adds `driver.readiness.invoker`,
  `driver.readiness.threaded` and `struct.size.readiness`.

- R-CORE-34 follow-up (karyos#809): `DriverConfig::max_stream_bytes`.
  - It is the most bytes one stream lane may take: its log buffer region
    plus its conflation table's, by `karyos_driver::stream_lane_bytes`
    (new, public).
  - Every lane the driver makes is checked against it: `add_stream`,
    `add_aggregate`, network publications, replay targets and a
    reconfiguration's successor. A guard reincarnation keeps its stream's
    geometry, so it stays within the cap.
  - A larger one is refused with the new `DriverError::StreamTooLarge`,
    and nothing is created.
  - A configuration a buffer or a table refuses keeps its own error,
    whether the cap is set or not.
  - A C host's `karyos_driver_add_stream` gets
    `KARYOS_E_INVALID_ARGUMENT`, with the lane's bytes and the cap in the
    detail.
  - A client's network publication above the cap is refused with the new
    wire code `StreamTooLarge` (24); a C client gets `KARYOS_E_REFUSED`,
    detail code 24.
  - `None`, the default, bounds nothing; `Some(0)` is refused.
- With the cap set, the sizing report adds two bounded figures and no
  longer excludes added streams, replay targets or network publications
  (`EXCLUDED_CAPPED`). A declared stream above the cap is refused.
  Without it, the report is unchanged.
  - The bounded figures assume no incarnation a guard close replaced is
    still retiring (`BOUNDED_ASSUMPTION`), and the report says so.
  - Bounded steady state: the regions that are not streams, the heap
    budgets, and `max_streams` lanes at the cap.
  - Bounded restart peak: bounded plus every lane's retained generations
    at the cap.
- `karyosd --max-stream-bytes <size>`. It rejects 0.
- `LogBuffer::<SharedTerms>::structure_length` and
  `ConflationConfig::structure_length` are available on every platform.

- `karyos_driver_options.max_stream_bytes` (ABI 0.1.5, karyos#818): the
  R-CORE-34 stream cap for a C host. 0, the default and an older caller's
  struct's, sets no cap.
  - `karyos_driver_add_stream` above the cap is `KARYOS_E_INVALID_ARGUMENT`
    with the lane's bytes in `code` and the cap in `value`.
  - A client's `karyos:udp` publication above it is `KARYOS_E_REFUSED`,
    detail code 24.
  - `karyos_driver_options` is 80 bytes.
- The conformance suite adds the feature `stream-cap` (floor ABI 0.1.5),
  with `driver.create_capped` and the scenario `op.stream.cap`; the suite
  itself still needs 0.1.3.

- Forward-compatible CnC refusal codes (karyos#819): an `Error` response
  whose code this peer does not define is read as a refusal,
  `ErrorCode::Unknown(UnknownCode)`, with its code and detail kept,
  instead of an undecodable response that left the request to time out.
  New public API: `ErrorCode::Unknown`, `UnknownCode` (its wire value,
  built only by the decoder), `ErrorCode::from_wire`,
  `ErrorCode::is_defined`, `ErrorCode::ALL` and `ErrorCode::HIGHEST`.
  Codes 0 and `u64::MAX` stay reserved. `ErrorCode::Unknown` re-encodes
  to its own wire value. The defined codes are one table, from which
  `code()`, `from_wire` and `ALL` are generated, so a new code cannot be
  left undecodable. A C client gets `KARYOS_E_REFUSED` with the raw code
  in `detail.code`. The driver never sends an undefined code (a debug
  assertion checks it in debug builds). The admission `VERSION` stays 3;
  RELEASING.md requires this change in the next release.

- The conformance op `subscription.await_image` and its feature
  `image-wait` (karyos#830, added by #835): it waits, serving every
  client, until a subscription has reported `count` images. Each round
  reads the pending image changes and answers the first that holds, in
  this order: a failing `karyos_subscription_next_image_change`'s status;
  `ok` once `count` is reached, even when changes were dropped; then, and
  only then, a failing `karyos_subscription_image_changes_lost`'s status;
  `events_lost` for a cumulative lost count above 0; `timeout` past the
  deadline. Every runner answers the same; the Rust runner and its
  precedence test share one function.

- `ContextBuilder::attach_timeout` (and `Context::attach_timeout`): the
  longest wait per message of `Client::connect`'s attach, apart from a
  control call's timeout, which it defaults to; once attached, the
  session's fetches of a grant's regions wait the call timeout again. A
  client whose calls time out fast need not attach as fast.
  `karyos_client::ipc::attach_with` takes both, and
  `karyos_sys::ipc::set_timeouts` and `receive_timeout` set and read a
  socket's (karyos#851).

- `NetworkConfig::endpoint_tables` (`EndpointTables`) sizes each
  endpoint the driver opens: TX slots, queues and routes (defaults 256,
  64, 64).
- `NetworkPublicationState::Limited(EndpointLimit)`: accepted, but its
  sender's open is refused for an endpoint limit; it sends nothing until
  it opens. The sender reports it with `AgentEvent::PublicationLimit`,
  once per epoch, and its end at the open.
- `SocketsTx::commitment` (`TxCommitment`): what a TX half has open.

- `bindings_adopted` and `bindings_adoption_refused` sender counters: an
  SM from a second source of a bound receiver adopts a binding of its
  own, at most `MAX_PATHS - 1` per binding an answer created, removed
  with it; one more is refused and leaves no state.

- The driver publishes each stream lane's wire `stream_id` and its
  publications in the counters region (karyos#885), so a tool can tell
  which wire stream a lane carries and count its publishers. Each lane
  has a `stream wire id` gauge, with the lane's stream keys, whose value
  is the `i32` id zero-extended (`karyos_sys::counters::wire_stream_id`
  reads it back, a negative id included), and an `embedded publications`
  gauge counting the embedding program's live publication handles on it,
  a pending cutover's included. Each client publication has a
  `publication` gauge keyed `KIND_PUBLICATION` with its registration id,
  whose value is its client's id. A lane's publications are its
  `publication` cells plus its `embedded publications`. All are kept by
  the positions pass and change no layout version; at the default limits
  the default region holds every cell.

- `AgentConfig::max_destinations`, the most destinations of one
  multi-destination publication: 1 to 64, default 16 (MD-6;
  karyos#889). Every per-destination share of the repair tables divides
  by it (MD-8), and a publication answers `Full` past it. A value
  outside 1 to 64, or above the endpoints' `max_routes`, is refused at
  driver start with `DriverError::MaxDestinations`, and a repair table
  with less than one entry per destination with `InvalidConfig`. The
  constant `MAX_DESTINATIONS` is replaced by `DEFAULT_MAX_DESTINATIONS`
  and `MAX_MAX_DESTINATIONS`.

- A dynamic subscription's registration is visible to its application
  (#941): `EmbeddedDriver::network_registration_state` returns
  `Registering`, `Announced`, `Refused` (an ERR REGISTRATION from
  `control`) or `Bound`, and the receiver publishes the CnC cells
  `registers sent`, `registers unsent` and `registration refusals
  received`. They are appended to the receiver's cells, so the ids of the
  cells allocated after them move by three; readers find cells by label.

### Changed

- `ConflationConfig` gains `refresh: bool` (ADR-0080, karyos#634), with
  `ConflationConfig::new` and `with_refresh`. A struct literal outside the
  crate must name it (`refresh: false`). With `refresh` false a view
  behaves as before: a reserved value outside `0..keys`, refresh cycle
  traffic included, is a rejected key. `ConflationShape` gains the same
  flag, and a log buffer's configuration block carries it in word 21; a
  reader that does not know the word refuses a block with the flag set
  and reads one without it as before.
- `karyos_cluster::dedup::DedupConfig::default()` is no longer the
  512 MiB configuration (karyos#692; item 37 of the decisions of
  2026-10-21, a named large profile rather than a hidden default). The
  default profile keeps 64 replies of 8 KiB and the 60 s TTL for 64
  sessions, 33,590,272 bytes per replica; `DedupConfig::large()` is the
  1024 × 64 × 8 KiB profile, 537,444,352 bytes per replica.
  `DedupConfig::reserved_bytes()` publishes what `SessionTable::new`
  reserves, metadata included, and a test checks it against the
  allocation. `DEFAULT_SESSIONS` is 64; `LARGE_SESSIONS` is 1024.
  A deployment that needs more than 64 sessions names
  `DedupConfig::large()`; with `default()`, the 65th live session is
  `RegisterError::SessionsExhausted`. The numbers stay provisional until
  plan issue 069 (karyos#685) measures them.

- A channel URI list that names one address in two spellings is refused as a
  repetition: `destinations=10.0.0.5:1;[::ffff:10.0.0.5]:1` and
  `paths=10.0.0.7;::ffff:10.0.0.7` are now `InvalidValue`, as an exact repeat
  already was. An IPv4-mapped IPv6 address compares equal to the IPv4 address it
  maps; IPv6 zones still tell addresses apart.
- `AgentConfig::conductor_duty_period` (default 1 ms) is a new public field: the
  longest time between two conductor duty cycles, which `barrier_ack_timeout`
  is validated against (karyos#658). `AgentConfig` is not `#[non_exhaustive]`,
  so a caller that builds it with an exhaustive struct literal must add the
  field; `..AgentConfig::default()` keeps working. karyosd bounds its idle
  sleep by it; a caller that drives an embedded driver's `duty_cycle` itself
  must call it at least this often while a conflated network view is open.
- **Admission `VERSION` 3.** Alpha.2 published version 2, and its in-place
  window closed with that publication
  (`owner-decisions/2026-10-21/decisions.md:64` to `:69`). The new commands
  therefore need a new version. A client and a driver of different versions
  are refused at admission with `INCOMPATIBLE_VERSION`: an alpha.3 client with
  an alpha.2 driver, or the reverse, in either combination. The C ABI's
  `KARYOS_PROTOCOL_VERSION` is 3.
- **`karyos_protocol::cnc::Command` is no longer `Copy`**, since a command with
  roles owns their lists. This is a public API change: code that copied a
  command clones it.
- A network publication runs the strategy its channel's `fc` names: `fc=max`
  and `fc=tagged:<group>` are granted instead of refused with
  `UnsupportedChannel`. The `fc` is the one source of the strategy: typed roles
  that name another one are refused with `DriverError::StrategyConflict`.
  `fc=tagged:0` names no group and stays refused (`UnsupportedChannel`).
  Decided 2026-10-27 by QS-COORDINATOR under owner delegation (karyos#637).
- `barrier_ack_timeout` is refused below 10 ms (`BarrierAckBound::Floor`) and
  below ten `conductor_duty_period` (`BarrierAckBound::DutyPeriods`), each with
  its own refusal: `AgentError::BarrierAckTimeout` from the agents,
  `DriverError::BarrierAckTimeout` at driver start (previously an untyped
  `InvalidConfig` for the floor only, and no duty period check).
- A conflated network subscription of an unreliable channel is refused with
  `DriverError::BarrierAckTimeout(BarrierAckBound::FarWindow)` unless
  `max(gap_reorder_timeout, path_skew_window) + barrier_ack_timeout` is below
  `far_window_timeout`. The far-window clock starts at the first `Ahead`
  arrival, while the fail-safe counts from the hole's post, so a longer timeout
  could let the far-window close end the image before its view closes. A
  reliable channel never closes by that timer and is not checked. Decided
  2026-10-27 by QS-COORDINATOR under owner delegation (karyos#658).

- `karyos-feed` depends on no crate (it depended on `karyos-client`), and
  `karyos-bench` and `karyos-tools` no longer declare it: neither used it.

- The C5 harness's linearizability check holds the test service's state
  as a shared log (karyos#687): a step shares the earlier values instead
  of copying them, and the search's memo hashes a state by its length and
  digest while comparing states value by value, so a digest collision
  never makes two states equal. A W2 burst of 4,096 client sessions is
  checked in about 7 s in a release build, where the copying model took
  over 10 minutes.

- Trace export (R-CORE-13, follow-up to the #826 review): when the page's
  first record's journal stays busy past the wait, all of that journal's
  records in the page go out `unreadable`, not only its leading run, so a
  stuck entry costs one wait per page instead of splitting pages into
  runs; the page ends at the first record of another journal left unread.
  The trade-off: those records are uncalibrated, even the ones the entry
  would have calibrated had it come free. The recycle log has its own
  1 ms wait after the table's, each part retrying its busy entries at
  least once and overrunning its wait by one yield and one read at most,
  so a stuck table entry no longer leaves the log unretried. Known limit:
  the agent remembers no stuck entry across requests (that needs the
  entry's version word in the reader API), so each request whose records
  name a journal not found while an entry is stuck waits again, about
  1 ms for each part that holds a stuck entry. `TraceMirror::hold_log`
  (karyos-sys `test-hooks`) holds a log entry mid-write.

- `GuardRate` and `AuditOutcome` are `#[non_exhaustive]` (karyos#740).
  Build a `GuardRate` with `GuardRate::publication(policy)` (or
  `GuardRate::scoped(scope, policy)`) and `.with_reserve(rate)` for the
  new control reserve; a reserve the policy itself crosses is refused at
  `guard_stream`. `GuardSpec` has a new `policy` field, the gate's slot.

- The driver validates a policy's control reserve against the same
  aligned charge as its byte burst, the MTU aligned as a frame: on an MTU
  that is not a multiple of 32 the reserve's byte floor is higher than
  before (for an MTU of 1400 and a reserve of 10 messages a second, 14 080
  bytes a second rather than 14 000).
- A policy a sender gate refuses is applied as the stricter of it and the
  policy in force, unvalidated on purpose: a byte bucket no datagram fits
  holds the lanes until a valid version (fail closed). Docs only; the
  behaviour is #841's.
- The CnC counter docs size the region for 6 cells per network
  publication (`network admission` and `network rate policies refused`
  added), not 4.

- The binding conformance suite's `FORMAT.md` states the version rule
  for a runner with no ABI version (karyos#751, decided in
  quantstratum-docs#498). Such a semantic runner checks
  `karyos::CORE_VERSION` and `karyos::PROTOCOL_VERSION` against the
  core release and protocol version it pins, before any other call;
  compares each scenario's `abi` with the ABI version its pinned core
  release declares; and answers `op.library.version` with the core
  release and protocol version, required from step B1 (at B0 it is `later`, the one `later` its B0 release allows). The release rule
  "no skip" reads "at the core release it targets" for that runner. The
  C ABI runners are unchanged.

- Backend contract (R-CORE-44, karyos#770): `ReturnReason` gains
  `NeighbourUnresolved` and `NeighbourTableFull`, which a backend that
  resolves neighbours itself (a native backend in exclusive mode) returns
  from a flush with the frame intact, never exposed. `ReturnReason` is now
  `#[non_exhaustive]`: the backend contract types have no stable contract
  version yet (R-CORE-26), so a backend's exhaustive `match` over it needs
  a wildcard arm. Sockets never return either reason; the driver counts
  them as any return.

- Item 57's audit findings (karyos#777). `karyos::ConflatedBudget`
  (`karyos_sys::conflation::Budget`) is built with `Budget::new(keys,
  retries)` and is `#[non_exhaustive]`, so a later bound is not a breaking
  change; a struct literal outside its crate no longer compiles. Both
  arguments stay valid at 0, as before: `keys` 0 makes a poll a no-op,
  `retries` 0 counts as one. The facade re-exports `Overrun` and
  `SnapshotFailed` at its root beside `SnapshotSource`, so an application
  implements the trait from `karyos` alone (`Overrun` stays under
  `karyos::embedded` too), and the trait's doc states that a method added
  later comes with a default body (owner item 41).

- A C host that never calls `karyos_driver_startup_complete` reads
  `KARYOS_READINESS_FAILED` once `startup_timeout_ns` (30 s by default)
  has passed. Nothing else in the driver depends on it.

- The Cluster's log entries are schema 2 version 1 (SPEC §8.5;
  karyos#797), over the ADR-0036 envelope of `karyos-codec`, instead of
  the unreleased internal version 1 envelope.
  - `karyos_cluster::service::Envelope` encodes and decodes the five
    templates (`Register`, `Close`, `Request`, `TimerFired`,
    `Configuration`) with their value rules and bounds; `to_vec` now
    returns a `Result`.
  - `ApplyError::Envelope` carries the codec's error. A payload that is
    not a schema 2 message is a safety stop: every replica stops at the
    same index.
  - `EnvelopeError` and `ENVELOPE_VERSION` are removed.

- `make pre-push` gains `lint-linux`: clippy for `aarch64-unknown-linux-gnu`
  with every feature, so Linux-only code is checked before a push from any
  host (RELEASING.md; a follow-up of karyos#798). The conflation tests'
  Linux-only module builds its configurations with
  `ConflationConfig::new`, so a field added later no longer breaks it, and
  the ignored probe measurement may print its quantiles.

- Multi-destination unicast repairs within the configured tables, and
  catches each destination up alone after an endpoint reset (MD-8, MD-20,
  karyos#802).
  - **The reset:** a reliable publication no longer rewinds its shared
    readers and resends to every destination. Each destination gets, per
    lane, one repair job over what it lacks:
    - it starts where its own submissions stop, at its `high`, or lower
      where a head was returned unsent earlier in the epoch (a later
      submitted head would otherwise pass that hole);
    - it ends at the readers' position;
    - nothing goes to a destination that already has it.

    The job takes a slot in the destination's share with no admission and
    no ERR. What it submits is the destination's: as the backend submits
    it, the destination's frontier advances, so its NAKs, the retention and
    a later reset start from there. A full share leaves the catch-up waiting
    to be tried again from its start past the floor, and
    a part below the retention floor is counted lost
    (`catch_ups`, `catch_ups_full`, `catch_up_lost` in the repair counts).
    Nothing else changes for that part: the receiver NAKs the gap, gets
    the usual ERR `RangeUnavailable` and applies its gap policy, as for any
    NAK below the floor. The rewind it replaces never went below the floor
    either.
  - **The tables:** the ERR linger entries, the job linger entries and the
    step 8 replies are now shared out per destination as the job table is,
    `value / max_destinations`. A value below one entry per destination is
    refused (`RepairConfigError::TableShare`). The tables of every
    destination together stay within the configured ones, and the sender's
    reply list holds every destination's ERRs, so none is dropped for room.

- A late multicast subscriber binds faster under loss (karyos#839, plan
  164). An unanswered SOLICIT is retried by the receiver's duty after 50
  ms, the wait doubling up to `setup_challenge_timeout`, for at most 6
  SOLICITs within twice `setup_challenge_timeout` of the first; each
  retry carries the entry's nonce, so an answer to any of its SOLICITs
  binds within that window, as for a resent CHALLENGE. A retry the
  RSP_SETUP rates refuse is not an attempt (`solicit_retries_refused`).
  Measured on Linux netem, 200 late joins: the p99 bind time is 53 ms at
  2% loss, 153 ms at 10% and 353 ms at 20% (about 2 s, 4 s and 8 s
  before), and back-to-back joins show no 2 s steps (p99 153 ms). At an
  RTT of about 200 ms and 2% loss a join takes about one RTT (median 201
  ms, p99 251 ms).

- The driver takes a remote client's `Leave` with a fetch outstanding (a
  fetch whose reply the client abandoned, or exports it has not detached)
  as a clean leave, not a protocol error (decided by QS-COORDINATOR,
  karyos#851): the client is no longer served, what was exported stays
  charged until its exit proof, and the new fixed counter `fetches
  abandoned at leave` counts it; `clients faulty` no longer does. This
  touches the admission code of karyos#831 (`Leave` acceptance).

- Follow-up to the #852 review (R-CORE-21): a reincarnation's network
  sender gate starts its bucket as if empty when the reincarnation began
  (`GuardSpec::empty_since`, the time its handles' rings carry), not when
  its agent took the guard, so the gate and the handles' copies agree.
  `EmbeddedDriver::backdate_next_reincarnation` is behind the new
  karyos-driver feature `test-hooks`, never in a release build. The
  `REINCARNATED_AT` docs name what orders the word before a handle reads
  it and what a reader in another time namespace sees.

- API: `NetworkPublicationState` is not `#[non_exhaustive]`, so its new
  `Limited` variant breaks an exhaustive `match` in client code, and
  `NetworkConfig` gains a public field, which breaks a struct literal
  without `..NetworkConfig::default()`.

- A network endpoint's tables default to 1024 TX slots, 256 queues and
  128 routes (were 256, 64 and 64; karyos#859, plan 168): about 110
  reliable single-lane publications per endpoint instead of 24, for
  about 1.5 MiB per endpoint (1448 bytes per slot, 64 per queue and
  192 per route on Linux). Decided 2026-10-29 by QS-COORDINATOR under
  owner delegation: 24 publications per endpoint was too low for the
  core, and 1.5 MiB per endpoint is acceptable on a server. `NetworkConfig::endpoint_tables` sets them.
  The driver's own caps now bind first for single-lane publications:
  `AgentConfig::publications` (64 network publications) and
  `max_streams` (64 local streams, one per lane); an endpoint's tables
  bind first only for multi-lane ones (a four-lane reliable publication
  takes 33 slots, 30 per endpoint).

- A SOLICIT for DATA that arrived on a multicast receive endpoint now
  leaves from the driver's unicast control endpoint of its address
  family, opened with the first multicast subscription and closed with
  the last (karyos#873, plan 169). The drivers of one host, which share
  the group port, are no longer one source to the publisher's
  `setup_answer_rate`. A unicast subscription's SOLICITs leave from its
  own endpoint, as before.
- The sender binds a receiver by its boot id: an SM matches its binding
  by sender endpoint, alias, boot id and incarnation, and the first
  accepted SM sets the binding's SM source, which never changes; NAKs,
  ERRs and RTTMs match and reply on it. In the trusted profile the boot
  id, not the source address, ties an SM to the receiver that solicited.

- The wire compatibility matrix's admission entries say why the refusal
  still names no driver version between 0.1.0-alpha.2 and main
  (karyos#879): a main driver states its version, but a 0.1.0-alpha.2
  client does not read it and a 0.1.0-alpha.2 driver states none.

- A driver that refuses a client's, tool's or probe's protocol version
  now states its own in the refusal (karyos#879): word 1 of `Refused`
  with `INCOMPATIBLE_VERSION`, 0 before, is the refuser's version. The
  layout and its length are unchanged, so every client of every version
  decodes it as before. `AttachError::IncompatibleVersion { driver }`
  and the C ABI's `detail->value` report it; a refusal of
  0.1.0-alpha.2 or earlier states none and still reports 0. Read it
  with `Message::refuser_version`, build it with
  `Message::incompatible_version`; word 1 of every other refusal stays
  the fetch id.

- A sockets TX half dropped outside unwinding with pending items no
  longer panics in a debug build (karyos#880). It is counted in
  `tx_discarded_on_drop` in every build, as release builds did, and
  remains a driver bug: `reset` and `retire` are the shutdown paths.
  The default-interface multicast test retires its nodes on every skip
  path, an item left pending included, so a host without a multicast
  route records a skip.

- The agent's join registry observes `stream` entries (karyos#885):
  `present`, `holders` and `shared` count the publications of every
  lane whose `stream wire id` cell names the entry's key, a client's
  `publication` cell each plus the lane's `embedded publications`. They
  stay `null` while the driver is not attached, before its first
  positions pass, and while `counters unavailable` is nonzero, so a
  shared stream is never shown unshared; a count that would overflow
  is unknown too.

- The agent's join registry follow-ups (karyos#893). A `join-list`
  cursor is checked as a key, as `join-get` checks one: a malformed or
  oversized cursor is refused. The registry's version number,
  `history_dropped` and `evicted` counters refuse a put that would pass
  `u64::MAX` with `{"error":"counter overflow"}`, and a refused put
  changes nothing (SPEC §14). `join.memory_bytes` is now a true bound,
  7 208 960 bytes: the counting allocator measures a registry filled to
  every bound at 7 057 552 bytes held, which the earlier 6 864 896 did
  not cover. Property tests cover the join request parser, the
  registry's bounds and the exporter's token check. The exporter answers 400 to a head with a header line that is not
  UTF-8, instead of reading only the headers before it, where an earlier
  `Authorization` could have been taken for the last one.

- CI checks RustSec advisories with `cargo deny check advisories` in a new
  `Advisories` job, separate from the `Licences and sources` job so an
  advisory database update does not hide licence, ban or source results.
  `make pre-push` stays offline (karyos#933).

### Removed

- The unused `karyos-feed` and `karyos-bench` aliases in the root
  `[workspace.dependencies]`, which made Cargo warn
  (`cargo::unused_workspace_dependencies`) under the pinned Miri
  toolchain (karyos#901). No member used either.

### Fixed

- The alpha.2 release notes stated that "A conflated view closed at
  `barrier_ack_timeout` is recreated with every key stale"; it was not
  implemented until this change. That limitation's two halves, the missing
  recreation test and the missing duty period check, are both closed here
  (karyos#658).

- The test kit's `karyos_test_panic_next_duty_cycle` arms its fault
  inside the driver table's guard (karyos#699). A close racing the arm
  either comes after it and disarms it, or makes the arm fail with the
  handle's error; the fault is never left armed on a closed driver.

- Rate policies at a reincarnation (R-CORE-21, follow-up to the #841
  review): a handle bound to a reincarnation of its publication (an
  incarnation past the first), in process or remote, starts its rate copy
  empty at the time the reincarnation began and has earned since, as the
  reincarnation's sender gate has: reincarnating buys no new burst, and a
  handle bound later is not stricter than the gate
  (`GuardBinding::reincarnated_at`, decided by QS-COORDINATOR). The driver
  writes that time, host monotonic nanoseconds, in header word 13 of each
  handle's outcome ring (`outcome_ring::REINCARNATED_AT`, reserved and zero
  before, so no layout change); a handle that reads 0 (the first
  incarnation, or a driver that predates the word) starts empty.

- The netem test N6 no longer fails intermittently (karyos#790). A
  multicast subscriber that missed the SETUP binds through a SOLICIT. A
  lost SOLICIT or challenge is retried only after the setup timeout and its
  holdoff, and under netem loss that could take longer than the publisher
  took to offer its 1000 messages. The image was then installed at the
  head with nothing left to read, and the test waited for a message that
  never came. The protocol behaved as specified: the test now publishes
  500 messages past the later of the two installs. The new
  `n6_a_late_multicast_subscriber_reads_the_stream_from_its_join` joins
  one subscriber after the first 1000 messages, and fails without the
  tail.

- The IPC descriptor count test no longer fails intermittently
  (karyos#804). It counted the driver process's descriptors after the
  warm-up client exited, but the thread draining that client's stderr
  closes its pipe at end of file, asynchronously. When the thread was
  late, the first count included the pipe, which then closed during the
  rounds, and the second count was one lower. The test now waits for the
  drain thread before each count. A failure names the descriptors that
  appeared or went.

- An unreliable lane now reports a lost tail as a local gap (karyos#806).
  When the last messages were lost and the sender went idle, only its
  heartbeat showed the tail, and the receiver ignored it: the loss was a
  silent hole, and N1 failed about one run in thirty. A fresh heartbeat
  above the covered end now opens a hole up to its position, never past
  a recorded terminal bound, and sealed as `ReorderExpired`.
- Each lost range ages from the moment it was revealed. When an open
  hole grows, through a higher heartbeat or DATA above it, the new part
  has its own detection time and its own `gap_reorder_timeout` deadline,
  and the older part keeps its own. Each part is sealed at its own
  deadline with its exact range: data of a newer part that arrives
  before its deadline is delivered, and a hole that keeps growing still
  seals its oldest part on time. Data that arrives before a part's
  deadline leaves nothing of it to seal. A reliable lane still NAKs its
  tail.
- This covers single-path publications. A redundant-path publication's
  `PATH_HB` names no position, so an unreliable redundant-path image
  still cannot see a lost tail.

- Follow-up to the #814 review (R-CORE-21, karyos#740):
  - A network sender gate built for a lane guarded with no rate creates
    its bucket from the first policy published to its slot, so a rateless
    lane's publication getting a policy is limited at the gate too, not
    only in its handles. Positions such a gate let through before are
    exempt: never charged, never refunded into the adopted bucket, and
    never charged again for another route's copy.
  - A bucket created for a policy taken at run time, the gate's or a
    handle's copy, starts empty (`RateLimiter::empty`): a change never
    grants tokens. A handle that binds to a policy in force, read whole,
    starts full, as a lane guarded with it does; one whose read at bind
    found the policy being written starts empty. A reincarnation's gate
    starts its bucket empty (`GuardSpec::full`), so reincarnating never
    buys a new burst.
  - The driver validates a byte burst against the largest charge its
    sender gate does, the MTU aligned as a frame (it used the MTU), so a
    policy it accepts and audits is never one the gate refuses. Were the
    gate to refuse one anyway, it fails closed: it limits with the
    stricter of that policy and the one in force, counted in the new
    per-publication CnC cell `network rate policies refused`, which the
    agent reports.
  - A gate built for a publication whose policy changed starts from the
    policy in force. Freeing retired streams drops the freed
    publications' stored policies in one pass over the lanes left.
    `GateCounts` is `#[non_exhaustive]`.

- Multi-destination unicast, the follow-up of its run-time destinations
  (karyos#822, plan 157):
  - A publication removed before the sender's next duty now closes the
    routes and queues of the destinations retired since that duty's
    drain; they used to stay open until an endpoint epoch change.
  - A removed destination is retired as a removed publication is: its
    removal is reported in the cycle it happens, whatever the state of
    the publication (served or not, established or not) or of its
    queues (an endpoint reset included), and it is retired at that
    report, with its quarantine counted from its removal (MD-14). Its
    route and queues go to the sender's close list: items still pending
    in its queues come back as `QueueClosed` and are counted in
    `removed_returned` and `removed_closed` (both now cover retired
    destinations too). Handles of an epoch older than the publication's
    died with that epoch and are dropped. The report hands its route and
    queues to the close list, which frees its slot for the next cycle's
    commands; that cycle's duty closes them before it opens any new
    route or queue, so a new destination never opens beside an old
    route. While the conductor's event ring was full, remove and add
    churn grew the per-destination state past `MAX_DESTINATIONS` and
    allocated on the duty path; an addition now answers `Full` instead,
    and a move at capacity retried after the removal shows in
    `network_removed_destinations` finds the slot free. A removal, a
    refused addition, a report with its retirement and the drain allocate
    nothing; only an accepted addition does. A close entry whose
    endpoint's TX half is not held at its duty (the half is in a reset,
    which drops the handles, or retired), or is of another epoch, is
    dropped and counted once (`removed_dropped`); a handle already gone
    counts as closed. An entry whose queue still has frames in flight is
    closed again at each duty (`removed_close_deferred`) and counts as
    failed only on a close error or after `CLOSE_IN_FLIGHT_TIMEOUT` (1 s)
    in flight (`removed_close_timeouts`): a kernel backend shows no
    progress on frames it holds, so a cycle count would fail closes that
    are only slow. One that finds no room to wait stays in the close
    list for the next duty (`removed_close_overflow`), never failed; one
    with a live handle the endpoint will not close is counted once
    (`removed_close_failed`). When that endpoint then refuses a route or
    a queue for its limit (`RouteLimit`, `QueueLimit`, `OverCommitted`),
    on any open path, in the same epoch, its reset is asked for once,
    tagged with that epoch; the served reset starts a new epoch, which
    drops what did not close. The endpoint table keeps this standing
    request while the endpoint is not active or within its interval, and
    serves it once in that epoch; with its command ring full it is
    counted refused once and tried again at most once per endpoint
    interval (`standing_retries`); an agent gone, or a new epoch, drops
    it (`standing_dropped`). An ordinary request refused meanwhile leaves
    it kept. Other reset requests are dropped then, as before,
    and asked again by their owner while the need holds. Without a
    failed close in the epoch the limit is an ordinary refusal and
    resets nothing. With the
    quarantine full, the record removed earliest makes room, the
    incoming one included; an incoming record already past its
    quarantine is not kept.
  - A route table, queue entries or TX slots that other publications
    filled (`RouteLimit`, `QueueLimit`, `OverCommitted`) no longer count
    as the destination's own fault, so an optional destination is not
    removed for them. They are counted in the new `endpoint_limits`
    counter; a reset or a stale handle is not.
  - A destination whose open failed is retried once per
    `setup_interval` in that epoch, at once in a new one, instead of on
    every serve.
  - A publication whose initial destinations are not all of the shared
    endpoint's address family, or whose endpoint address is unknown, is
    refused at creation (design 3.1). An unknown address is no longer
    taken for IPv4.

- With `max_stream_bytes` set, a conflation table the driver refuses (a
  value capacity past `u32`) keeps its own `InvalidConfig` on
  `add_stream`, `add_aggregate` and a reconfiguration, instead of
  `StreamTooLarge` (karyos#824).
- A client's network publication above the cap is refused with CnC code
  24 and the lane's bytes in the detail; a C client reads them in
  `detail.value` (karyos#824).
- `stream_lane_bytes` is `None` for a conflation table that a stream
  refuses, and the sizing report refuses such a stream as an invalid
  conflation configuration, with or without the cap. For every stream it
  accepts, the report's text without the cap is unchanged (karyos#824).

- Follow-up to the #831 and #837 reviews (karyos#827, karyos#824):
  - The drain of a remote client found gone reads a 0-byte datagram
    queued before its close as a datagram, not as the end of the stream,
    so the `Detach` behind it is served.
  - A failed `poll` of the peer reads as hung up: a real end of file is no
    longer taken for empty datagrams.
  - A closed client that gives no exit proof counts as faulty after its own
    bound (1 s), not `fetch_deadline`, and the driver logs a diagnostic
    naming the client.
  - A skipped `ECONNRESET` no longer takes a datagram of the drain's bound.
  - A closed client's time is the step's clock reading, and the exit
    check runs once per drain.
  - `karyos.h`'s `karyos_client_add_publication` says that an unsupported
    channel (CnC code 13) leaves 0 in `detail.code` and the stream id in
    `detail.value`, and an ABI test pins it.
  - The sizing report checks the stream cap with the driver's own check.

- An IPC driver now reads what an exited client queued on its admission
  socket before its exit proof releases it (karyos#827). A `Detach` the
  client sent before exiting ends its grant as a detach, so "grants
  detached" no longer misses it.
  - Only messages that release something are served; a queued `Fetch` is
    dropped.
  - An exited client is drained instead of served, never after its
    turn, so nothing is fetched or sent for it.
  - A client whose socket closes (end of file, `EPIPE` or `ECONNRESET`)
    before its exit is visible (Linux closes a dying process's
    descriptors first) is drained the same way, then retired, not as
    faulty, its slot charged until its exit proof: the new counter
    "clients closed before their exit". The end of file is confirmed with
    `POLLRDHUP`, so a 0-byte datagram from a live client stays a protocol
    error. A closed client with no exit proof within `fetch_deadline` then
    counts as faulty, and its slot stays charged until its exit proof.
  - The drain reads at most 1024 datagrams, the driver's own bound, and
    at most 8 exited clients are drained in one admission step.
  - Messages queued for the exited client are dropped unsent.
  - New driver counters: "grants released at exit" (grants whose
    descriptor left and that the exit ended), "fetches dropped at exit",
    "admission messages dropped at exit" and "admission messages not sent
    at exit" (each at exit or at a close before it), and "clients closed
    before their exit".

- A redundant-path publication's idle lane now sends the idle DATA
  heartbeat on every path that can send (karyos#834), as a single-path
  lane does on its one. Each path waits a whole interval after its own
  last DATA or heartbeat, and while any path holds a copy of the lane (its
  socket full, or returning to the live set; a path whose endpoint's half
  is not held at the epoch it opened in bounds nothing, as it can send
  nothing) every path's heartbeat stops at that copy's
  position: it never announces a position a held copy would still bring,
  and still reveals a tail lost below it. A tail above a copy held for
  long is revealed once the copy goes. PATH_HB still keeps each path's
  binding live (RP-3). A tail lost on every path is now revealed: a reliable image
  NAKs it, and an unreliable one seals it as a local gap at the reorder
  deadline, with its exact range. A tail lost on one path still arrives
  by the other. The cost while idle is one 32-byte frame per lane per
  path per `sender_heartbeat_interval`: N lanes over P paths send N × P
  frames each interval.

- Skip policy follow-up to karyos#821 (part of karyos#834). On an
  unreliable channel a data hole's part is seen up to the heartbeat's
  mark as well as the covered end, so a tail above a data hole ages from
  when the mark showed it. The receiver feeds every lane of an image up
  to its `lane_count` to the skip policy, each mark clamped to the
  lane's terminal bound. A reliable image's hole the receive owner cannot
  compute, a data hole or a heartbeat's tail, is counted in the new
  `hole_query_errors` receiver counter instead of being dropped
  silently, and a heartbeat mark off a frame boundary is rejected as an
  invalid gap. Tests cover the parts past their
  capacity, the clamped tail seal at the driver, and both seals of a
  tail across a term end.

- The sender's control routes take part in the #838 rule. A control
  route or queue refused for the endpoint's limit (`RouteLimit`,
  `QueueLimit`, `OverCommitted`), or a control route that will not
  close, counts as the data paths' do, so the endpoint's standing reset
  is asked for. An evicted control route whose queue still has frames in
  flight keeps its place in the cache, sends nothing more, and is closed
  again at each sender duty; it counts as a failed close only on a close
  error or after `CONTROL_CLOSE_TIMEOUT` (1 s) in flight
  (`close_timeouts`), and a burst of controls changes nothing of that.
  At most `control_routes` routes are open and as many closing, within
  the capacity allocated at creation. An ANNOUNCE refused while every
  cached route is closing waits in order and goes at the next send or
  duty, so every destination gets it: at most one waits per destination
  and publication, a later one replacing it in place, within room
  allocated at creation (`publications` × 16 per endpoint), so none is
  dropped. The new `controls_waiting` sender counter counts them. Any
  other control refused then is dropped and counted by kind
  (`blocked_status`, `blocked_naks`, `blocked_setup_answers`,
  `blocked_other`): SMs and NAKs are sent again periodically, and a
  SETUP answer is solicited again by its peer. A destination removed, or
  a publication removed, purges the ANNOUNCEs waiting for it. Open and
  closing routes together stay within twice `control_routes`, allocated
  at creation: a further destination is refused then, and no route is
  ever given up as failed to make room.

- Close and reset follow-ups to #838 and #849 (karyos#847).
  - Each failed control close is counted: `ControlRefusal::close_failed`
    is now a count, not a flag, so `removed_close_failed` counts every
    one.
  - A control route in flight uses the data paths' grace rule: a clock
    that steps back is no time elapsed.
  - Controls waiting when the endpoint moves to a new epoch are counted
    in `waits_dropped`.
  - A plain control send drains the waiting controls first and is
    refused (`Blocked`) while one to its destination still waits, so a
    receiver never sees a control before the ANNOUNCE it refers to.
  - A removed publication's route that the full close list cannot hold
    is recorded as its endpoint's close failure, so the standing reset
    drops it; it is still counted in `removed_unrecorded`.
  - A standing reset the ring refused and then dropped counts once in
    `resets_refused`.
  - A fault while the endpoint is not active doubles the next reset
    interval only while the last reset's interval still runs.
  - The control routes' counters are checked: an overflow sets
    `overflowed` and keeps the last value.

- A remote client whose fetch of a grant's regions timed out abandons that
  fetch, not its session: the manifest, arriving late, is drained at the
  next fetch (its regions closed and their exports detached), and the next
  fetch then reads its own reply. Before, the late manifest could be read
  as the next fetch's reply, which left the session out of step
  (karyos#851). A region that does not arrive still leaves the session
  out of step, now after the regions received are detached.

- A remote client releases a late grant even when the fetch that takes it
  times out (karyos#851). Before, the take failed, the release was not
  counted, and what the abandoned fetch exported stayed held until the
  client's next fetch drained it. Now `Client::poll` drains abandoned
  fetches without waiting (`RemoteClient::drain_abandoned`), so their
  exports are detached at once, and the release removes the grant's
  registration itself. The remote late-grant tests also retry a request
  whose fetch timed out under load.

- A remote client whose fetch times out after its manifest, while its
  regions are arriving, abandons that fetch with the regions still to
  come instead of leaving its session out of step (karyos#851): the
  regions that arrived are detached at once, and those that arrive later
  are drained one at a time, at the next poll or before the next fetch's
  reply, and detached. Draining at a poll never waits: it takes the fetch
  lock only if free, reads only what has arrived, and costs one load when
  nothing is abandoned.

- The remote reincarnation rate test ran at a thousand messages a second,
  so a bind delayed 2 ms under load already earned the burst it expected
  to be empty; it runs at ten a second now, with a 250 ms backdate for the
  burst case. The images-in-turn test states why its witness subscription
  proves the other's images hold their messages (karyos#856 review).

- The images-in-turn test (`client_facade.rs`,
  `a_network_subscription_polls_its_images_in_turn`) read before both
  images held their messages: under load, one image's datagrams arrived
  after the reads began, and the first reads rightly took the only image
  with data. A second subscription of the channel now witnesses that both
  images hold all 16 messages before the first is read one at a time
  (karyos#853, plan 167). No timeout is longer.

- A network publication its endpoint cannot hold is no longer accepted
  and silent (karyos#859, plan 168). The driver keeps what each
  publication takes of each endpoint it sends on (a reliable single-lane
  one: a route, 2 queues, 9 TX slots) with a reserve for the sender's
  control routes, and refuses an add past the endpoint's TX slots,
  queues or routes with `DriverError::EndpointCapacity`
  (`ResourcesUnavailable` to a client, the detail word
  `limit << 56 | capacity << 32 | needed`,
  limit 1 TX slots, 2 queues, 3 routes). The room of a removed
  publication is free once its removal has ended, so a refusal during a
  removal is retryable. With the defaults one endpoint holds 24
  reliable single-lane publications; before, the 25th and later ones
  were accepted and sent nothing, and a late subscriber could not bind
  them (the 19 s of plan 168).
- A destination added at run time to a multi-destination publication
  is checked against its endpoint as at the add and refused with
  `DriverError::EndpointCapacity`; from its post to its answer it holds
  its room, a refused one gives it back and a removal frees it at its
  report. A reliable multi-destination publication counts a repair
  queue per destination (it counted none: they open after the add).
- A refused network publication add leaves nothing behind: its stream
  key is free in the same cycle, so the same add retried at once is
  never `DuplicateStream` (it was for a few cycles).
- A refused open of a publication's route or queues counts in
  `endpoint_limits` for an endpoint limit and is tried again
  `setup_interval` later, not every cycle.

- An idle publication keeps its subscribers' paths (karyos#859, plan
  168). Every established publication now sends a PATH_HB on each idle
  path: one on one path, each path of a routed one, and each live
  destination of a multi-destination one, at most one per
  `path_heartbeat_interval`. A path with DATA in the interval sends
  none, nor a publication being removed or whose guard admits no lane.
  Before, an idle publication on one path, or to several destinations,
  lost each subscriber path at `path_liveness_timeout` and bound it
  again by SOLICIT, about one SOLICIT per path every 10 s.

- The multi-destination end-to-end tests no longer add fixed loopback
  ports a receiver may have drawn from the ephemeral range, which made
  an expected `Added` report `Present` (karyos#900). Each fixed
  destination is the port of a socket the test holds open.

- `RaftLog::entries` checks each frame against the in-memory index before it reads or allocates the payload, then checks its CRC-32C (karyos#904). The header must name the indexed index and term, and the header and payload must span exactly the frame's indexed bytes; the last frame must fit before the written end. Before, a frame corrupted on disk after the open was read silently: a wrong length returned a payload running into the next frame. Such a frame is now a typed `LogError::Chain`, with new `ChainProblem::Length` and `ChainProblem::Term` problems, and the read does not poison the log.

- The reference fixture refuses a membership change while a leadership
  handover is under way, naming the target as leader, as it already
  did for client requests (karyos#909). Before, the old leader could
  append a configuration entry the target never held, and the target's
  next term diverged from it.

- Dynamic registration, sender side (#940; behind the refusal of dynamic
  mode on the public API): a REGISTER at the per-source or the driver's
  pending bound replaces the oldest entry it competes with instead of
  being dropped, so spoofed REGISTERs from a required receiver's address
  no longer lock it out; REGISTERs and registrants' CHALLENGEs draw on a
  per-address bucket of their own, not on `setup_answer_rate`, and an
  address the full table cannot track is bound by the driver's total;
  the first SM must name the receiver block its REGISTER named, and a
  required id holds one slot for the publication's incarnation (its
  return at another endpoint is refused, as its membership holds it
  lost); an SM refused at a held slot leaves the slot to retire at its
  timeout; a restart replaces a binding only once it is quiet for
  `destination_move_quiet`; a source in its quarantine gets no ANNOUNCE;
  a receiver restarting at its own slot is not refused for a full quota;
  a CHALLENGE whose ANSWER is refused for its rate keeps its pending
  entry; on a dynamic publication an SM adopts no binding at another
  slot's address (it could claim a required id), every optional slot
  retires with the last binding at its address whichever path removes
  it (an eviction from a full binding table left it for good), and a
  required id whose slot is held with no binding is dropped at its
  REGISTER. The new counters `dropped_quarantined`, `pending_replaced`,
  `source_rates_full`, `dropped_challenge_rate` and
  `dropped_required_lost` are not in the CnC
  yet (#942 item 9), so no user can read them.

- Dynamic registration, receiver side (#941; behind the refusal of
  dynamic mode on the public API): three or more dynamic subscriptions
  registering at one `control` address now bind when their publisher
  starts after them. Their REGISTERs draw on a bucket of their own per
  `control` address at the receiver, and a registrant's CHALLENGE on a
  bucket of its own per address at the sender, so REGISTERs no longer
  spend the CHALLENGE that completes a registration; each key backs off
  from `setup_interval` to sixteen times it while nothing binds, starts
  over on an ANNOUNCE from `control`, and keys are spread within an
  interval. A required receiver id is no longer kept out by a full
  bindings table while it believes it is bound: the sender keeps one
  binding free per required id not yet joined, answers no CHALLENGE of a
  dynamic publication it cannot bind (counted `challenges_unbound`, and
  `bindings_reserved` when the kept binding decides), and refuses
  `receiver_bindings` below `max_destinations` at start and dynamic
  publications whose `max_destinations` together exceed
  `receiver_bindings` (`DriverError::ReceiverBindings`). On a registering
  key a SETUP ANNOUNCE or ANSWER is taken only from its `control` address
  (`setup_not_from_control`). A client's `control-mode=dynamic` URI is
  refused as `UnsupportedChannel`, not the retryable
  `ResourcesUnavailable`. A dynamic publication's allowlist with no range
  of `control`'s family, and a dynamic subscription's `control` no
  REGISTER can reach, are refused with errors that name them
  (`DriverError::Registration`, `DriverError::InvalidRegistrationControl`),
  as are more required ids than `max_destinations`
  (`RegistrationConfigError::TooManyRequired`, before `InvalidConfig`).

### Security

- `rustix` is updated from 1.1.5 to 1.1.6 in `Cargo.lock` (karyos#928),
  the fixed release for RUSTSEC-2026-0486 (the `rustix::fs` xattr
  functions marked unwritten bytes as initialised on a zero-length
  buffer). No other crate moves; `linux-raw-sys` stays at 0.12.1.

## [0.1.0-alpha.2]: 2026-10-21

Second alpha: cross-process data streams on Linux, the UDP transport, the
Archive with replay and recording groups, the management agent and tools, and
the C ABI (0.1.1) with its conformance suite. See
[RELEASE-NOTES-0.1.0-alpha.2.md](RELEASE-NOTES-0.1.0-alpha.2.md).

### Added

- The conformance suite gains feature `incompatible-driver` (Linux):
  SPEC.md §13's "older protocol version refused at admission" as two
  scenarios, `op.connect.refused` and `op.connect.other.version`. A
  test-kit binary, `karyos-admission-stub` (karyos-tools, built only
  with its new `test-hooks` feature), answers every `Hello` with
  `Refused` (`INCOMPATIBLE_VERSION`) or `Admitted` at the next protocol
  version, and `client.connect` takes an optional `dir` to connect
  there; both answer `KARYOS_E_INCOMPATIBLE_DRIVER`. The conformance
  test kit (`make libkaryos-testkit`) ships the stub beside karyosd,
  with its SHA-256 in the kit's MANIFEST. A runner without the
  provisioning declares the feature absent.
- The conformance suite gains feature `remote-driver` (Linux): the runner's
  karyosd gains a conflated stream (22), a guarded one (23) and a plain one (24)
  (karyos#585), and `$remote_client` is its client. `op.remote.conflated` reads
  a remote conflated view, and `op.remote.outcomes` a remote guarded
  publication's `Submitted` records. `publication.offer` takes an optional
  `reserved_value` (a conflated stream's key), and `conflated.poll` and
  `publication.poll_outcomes` an optional `until`, a count to poll for within 10
  s, since a remote driver answers after the offer. A runner retries an offer on
  a publication of a provided client (`$remote_client` or `$archive_client`)
  that answers `back_pressured` or `admin_action`, serving its client, for up to
  10 s, and each exclusive remote stream is added at most once per suite run
  (karyos#590).
- `karyosd --conflation <stream>:<session>:<keys>:<value>:<journal>` (the value
  and journal capacities are sizes) gives a configured stream a conflation table
  (an offer's reserved value is its key), so a remote client's conflated view
  can read it. `karyosd --guard <name>:<stream_id>:<session_id>:<messages>`
  guards a configured stream with guard `<name>`, which the daemon adds and
  opens once at start (the reopen is audited), so a remote guarded publication
  reads its outcome records. Each must name a stream a `--stream` configures,
  once. Closing or reopening a guard stays an operator action, and rate limits
  are not offered.
- `karyosd --stream <stream_id>:<session_id>:allow-unconnected` starts a
  stream whose publications offer with no subscriber attached, a remote
  client's included (its grant carries the stream's policy, #577).
  Without the suffix a stream refuses offers until a subscriber attaches,
  as before. The conformance test kit's karyosd takes the flag as built.
- The conformance suite gains `op.replay.u64` (feature `archive-replay`):
  a replay's `uint64_t` arguments past the signed range, as runners parse
  and pass them. The length 2^64 - 1, the ABI's "to the end", delivers
  the whole recording, and a position or a length of 2^63 is refused as
  an invalid request (code 4). FORMAT.md's Values says which results
  cross 2^63: no position nor `karyos_detail` value does, while about
  half of all handles do (their generation comes from a random base per
  copy), so each binding's own tests pin its unsigned reading.
- `make libkaryos-copies-check` (C-LINKAGE, not part of pre-push): two
  file copies of the package's shared library, loaded in one process with
  `RTLD_LOCAL`, each answer `KARYOS_E_CLOSED` to the other's driver and
  client handles (a use and a close), and keep their own usable. It
  prints both copies' base generations, so a collision is diagnosable.
  It passes on macOS and Linux; with a constant base it fails.

- The facade `karyos` crate re-exports `ImageChange`, `ImageEnd` and
  `SealReason`, and `karyos-client` re-exports `SealReason` at its root: a
  facade user drains a network subscription's image changes and reads each
  retired image's end without naming `karyos-client` or `karyos-sys`.
- A retired image's change carries how its stream ended. In `karyos-client`,
  `ImageChange.end` is an `ImageEnd`, the stream's terminal seal: its
  `SealReason` and its stream position. `EndOfStream` means the source's EOS was
  reached through a complete prefix. `ImageRetired` means the image retired
  without one: its publisher timed out, or a lane lost a frame. It is `None` for
  an arrival and for an image released unsealed. `ImageChange::with_end` sets
  it. `karyos-sys` gains `LogBuffer::terminal_seal`. In C, `karyos_image_change`
  grows from 24 to 48 bytes (`KARYOS_IMAGE_CHANGE_SIZE_ENDS`) with `end_reason`
  (a `KARYOS_END_*` code), `reserved`, `end_position` and `seal_code`, written
  by the caller's size: a caller of the 24-byte struct gets what it got before.
  The struct grew within the unreleased ABI 0.1.0, so the ABI version stays
  0.1.0, with no patch bump, as F9b and F9c did.
- The conformance suite gains the `archive-replay` feature (B6-3; ADR-0073
  format 2): ops `archive.connect`, `archive.replay`,
  `archive.stop_replay`, `archive.close` and `replay.subscribe`, the
  feature-free `subscription.poll_to_end` and `subscription.end`, and an
  Archive refusal's `code=` after `status=refused`. A runner provides
  the Archive with no Rust: it starts the pinned core's karyosd (the
  conformance test kit's, or one built with cargo) with an Archive that
  records stream 20 from boot, connects `$archive_client`, seeds
  "r0" to "r9" and binds `$recording` and `$recording_end`; Linux only.
  Three scenarios: a complete replay ends `end_of_stream` at its end; a
  stopped one `image_retired`; refusals carry codes 2 and 3, and a
  mismatched rate is refused locally.
- `make libkaryos-testkit` (`scripts/package-testkit.sh`) builds the conformance
  test kit beside a libkaryos package, in its own `<package>-testkit` directory:
  `bin/karyosd` from the package's core commit, for the suite's `archive-replay`
  scenarios, and a MANIFEST with `role=conformance test kit, not for release`,
  `core_commit`, `core_dirty` and `karyosd_sha256`. It refuses a package of
  another commit or tree state, and is Linux only (those scenarios connect a
  cross-process client). It is not part of the release package, nor of pre-push.
  A kit is not rebuilt with its package: a consumer checks that the kit's
  `core_commit` equals the package's before using it.
- `karyos-ffi` replays an Archive's recordings from C (F9c, B6):
  `karyos_archive_replay` (with `karyos_replay_options`, read by prefix) starts
  a replay and writes its id and its target's session id;
  `karyos_archive_stop_replay` stops it; and
  `karyos_client_add_replay_subscription` (with
  `karyos_replay_subscription_options`, null for the defaults) takes the replay
  target, `KARYOS_E_NOT_CONNECTED` until a `karyos_client_poll` has its grant.
  An Archive handle's first replay call opens control streams of its own, with
  the handle's next requester id, so replay and listing answers never mix.
  `karyos_subscription_end_state` (with the 24-byte sized struct
  `karyos_subscription_end`) reads how a stream subscription ended:
  `KARYOS_END_*`, with `END_OF_STREAM` for a replay that reached its end,
  `IMAGE_RETIRED` for one stopped, `STREAM_REMOVED`, `REVOKED`,
  `CLOSED_BY_OVERRUN`, and `OTHER` for any other reason, a newer core's
  included, with the raw seal code. A network subscription reads
  `KARYOS_END_NONE`: its images' ends come through its image changes.
- `karyos_client`: `From<ClientSubscription<T>> for Subscription<T>`, so a
  replay target granted by `Client::replay_targets` polls and is released
  (`Client::remove_subscription`) as any stream subscription.
- The C ABI's thread rules per handle kind (BIND-S2), in a "Threads" section of
  `karyos.h`. No handle has thread affinity: every kind may be created, used,
  moved and closed on any thread, and a claim committed on another thread.
  Concurrent calls on one handle are refused with `KARYOS_E_BUSY`, never
  serialized, and calls on different handles run concurrently: a data-path call
  holds only its handle, while a control call also holds the client. Two waits
  are bounded: a call on a started driver waits for one duty cycle, and ending a
  claim waits for the claim's slot. A started driver's thread now yields the
  driver to a waiting call before its next cycle, so a call waits through at
  most the cycle in progress: before, under busy-spin or sustained work, the
  thread could take its unfair lock back for an unbounded time. `karyos-ffi`
  asserts at compile time that each kind's object is `Send` and its table `Sync`
  (`src/threads.rs`), and `abi::tests::threads` checks the runtime rules.
- `karyos_archive::client::replay` (B6): a `Replayer` that starts and stops
  replays over the Archive's control streams for a requester that reads them
  elsewhere, such as a binding. It never blocks: `start` and `stop` queue a
  request and return its `RequestId`, and each `poll` sends what it can and
  reports one `Started` (with the target's session id), `Stopped`, `Refused` or
  `Expired`. At most `MAX_PENDING` (16) requests and unpolled answers wait, and
  nothing grows after `new`. A replay request that expired and is answered late
  has its replay stopped, so a request that timed out never leaves a replay
  running. A replay's end is its target's seal: `EndOfStream` when it ran to its
  requested end, `ImageRetired` when it was stopped; no control message tells
  the requester.
- Conformance scenario `op.claim.parent.close` (format 2, `claim-retry`,
  row "staged claims"): a staged claim ends with its publication's close
  and with its client's close, and its first op afterwards, an abort or
  a commit, answers `closed` (FORMAT.md, Close). `op.claim.retry` ended
  its claim by a commit first, so no scenario reached a binding's abort
  on a claim its parent had ended.

- The libkaryos package carries `lib/pkgconfig/karyos-static.pc` for a
  static link: `karyos.pc`'s `-lkaryos` makes the linker pick the shared
  library even under `pkg-config --static` (macOS ld, and GNU ld without
  `-Bstatic`), so `karyos-static.pc` names `lib/libkaryos.a` itself, with
  the archive's system libraries from rustc's `native-static-libs` in
  `Libs` (cgo's `#cgo pkg-config:` reads `--libs` without `--static`).
  Static means libkaryos only: the system libraries, `libgcc_s` on Linux
  included, stay dynamic.
  The MANIFEST lists both files (`pkg_config=`). `make
  libkaryos-static-check` links a C program of a few lines through it,
  with and without `--static`, runs `karyos_abi_version` and checks with
  `otool -L` or `ldd` that no libkaryos is loaded. It compiles C, so it
  is not part of pre-push, and the package script still compiles none.

- Conformance scenarios for the C ABI added since batch 1 (F6; SPEC §13). The
  runner (`tests/conformance.rs`, FORMAT.md) now calls
  `karyos_subscription_poll` (`handler` `"keep"`, or `"reenter"`, which polls
  the same subscription from inside the handler; results `delivered`, `last` and
  `reentered`), `karyos_publication_poll_outcomes` and
  `karyos_client_add_conflated_subscription`. New scenarios:
  `subscription.poll.reentrant` and `subscription.poll.bounded` now cover the
  §13 rows "reentrant poll" and "bounded poll stops on callback failure", which
  were pending; `outcomes.typed.statuses` and `conflated.client.view` join
  "typed status codes". "Kept fragment pointer" stays pending: a portable runner
  cannot see the library's mappings, and the library's own test covers it.
- `karyos-replay start` and `stop` (H6): ask a running Archive to replay a
  recording into a stream, or to stop a replay, over its control streams. `start
  --live DIR=REQ,RESP --recording ID --to-stream S [--from POS] [--length BYTES]
  [--channel URI] [--timeout-ms N]` prints `replay=ID stream=S session=N` for
  the reader, which the Archive waits for (H2b).
  `stop --live DIR=REQ,RESP --replay ID`. Exit status 2 on any error, the
  Archive's refusal included. They connect through `ArchiveConnection` (Linux),
  one connection per request, closed after it. `karyos_tools::args::parse_live`
  parses `--live` for these and for `karyos-catalog list --live`.
  `tests/karyosd_replay.rs` runs both against `karyosd --archive` (Linux).
  `--timeout-ms` (5000 by default) bounds each step: connecting, opening each
  control stream, then the request and its answer.
- Remote conflated views through the facade and the C ABI (F7b-2c-1):
  - `Client::add_conflated_subscription(uri, stream_id)` and
    `Client::add_conflated_subscription_with(uri, stream_id,
    ConflatedOptions)`: a view of a `karyos:ipc` stream's conflation table.
    A client attached to a driver in another process takes it; a client
    of a driver in this process is refused by its driver
    (`ClientError::Refused`), which gives in-process views itself
    (`EmbeddedDriver::subscribe_conflated`). Another channel is
    `ClientError::UnsupportedChannel`, before anything is requested.
  - `ConflatedOptions { budget, limits }` (`#[non_exhaustive]`; the
    default is the driver's view budget, 1024 keys and 3 retries, and the
    default limits), re-exported with `ConflatedLimits` and
    `ConflatedBudget` from the facade. `ConflatedLimits` moves from
    `karyos_client::ipc` to the crate root, on every platform
    (`ipc::ConflatedLimits` stays as a re-export), and gains `new`.
  - `karyos_client_add_conflated_subscription(client, uri, stream_id,
    *conflated, *detail)`: a client's view, closed with its client, after
    which its handle answers `KARYOS_E_CLOSED`. It takes the default
    retries and limits; the key budget is each poll's.
  - `AddConflatedSubscription` with session 0 names the stream a
    `karyos:ipc` URI of the id names, when there is one (the key is exact
    otherwise), and `RemoteClient::take_conflated` takes the grant's
    session for such a request, checking the stream id, as a request by
    URI does (W7).

- Conflated subscriptions over the C ABI (F7b-2b):
  - `karyos_stream_options` grows `conflation_keys`,
    `conflation_value_capacity` (u32) and `conflation_journal_capacity`
    (u64): an ABI addition, 80 bytes. All three 0 means no table; a
    partial set, or a table the driver cannot build, is
    `KARYOS_E_INVALID_ARGUMENT`. A 64-byte struct of the first layout is
    still accepted, with no table; a size between 64 and 80 is refused.
    `karyos_stream_options_init` now writes 80.
  - `karyos_driver_subscribe_conflated`, `karyos_conflated_poll` (a
    `karyos_conflated_handler` gets the key, the value from the reader's
    private copy, its version and its freshness: `KARYOS_FRESH` or the
    stale start) and `karyos_conflated_close`, with
    `KARYOS_MAX_CONFLATED_SUBSCRIPTIONS`. A stream without a table is
    `KARYOS_E_CONFLATION`; a closed view, or one of a closed driver,
    answers `KARYOS_E_CLOSED`.
  - Conformance: `conflated.typed.statuses`; `struct.size.stream.options`
    covers both layouts; the runner's three new calls and the stream's
    conflation arguments.

- Per-offer options (F7b-2a): the facade's `Publication::offer_on_with(lane,
  payload, OfferOptions)`, with `OfferOptions { reserved_value }`
  (`#[non_exhaustive]`; `Default`, `new`, `with_reserved_value`), and over the C
  ABI the new struct `karyos_offer_options` (`size`, `reserved`,
  `reserved_value`; read by prefix, 16 bytes in 0.1.0),
  `karyos_offer_options_init` and `karyos_publication_offer_with`. The reserved
  value is every fragment's header value, which subscribers read as
  `reserved_value`, and a conflated stream's key. A null options, a short size
  or a nonzero `reserved` is `KARYOS_E_INVALID_ARGUMENT`; a key or value the
  publication refuses is `KARYOS_E_CONFLATION`, with nothing reserved. Claims do
  not take options yet.
- `Subscription::rejoin_with(provider, secondary)` on the client facade (F9-0):
  a stream subscription becomes a `RejoiningSubscription` whose overruns are
  recovered from a `ReplayProvider`'s replays of its own publication and merged
  back into the live stream (`ReplayRejoin`), falling back to `secondary`. Its
  poll reports as `Subscription::poll` does, with a rejoin's outcome also
  reported on its own; `is_recovering`, `merge_failure`, `source` and
  `into_subscription` complete it. A network subscription, or one with no
  publication identity, is refused as `NotRejoinable`, the subscription handed
  back. The subscription's own rejoin policy is set aside while it rejoins and
  comes back with `into_subscription`. New public client surface:
  `Subscription::rejoin_with`, `RejoiningSubscription` and `NotRejoinable`.
- The facade's Archive-backed rejoin, polled as the C ABI polls, and its replay
  targets through the facade (F9b core).
  - `RejoiningSubscription::adopt`, `max_message_length` and
    `poll_adopted`, as `Subscription`'s. A holding poll moves neither
    the live reader nor a merging replay to a successor mapping. A
    replay handed out during it is read only after the next `adopt`,
    and only then counts in `max_message_length`, which is the larger of
    the live stream's and the replay's while it merges.
  - `Client::replay_targets()` gives a `ReplayTargetSubscriber`, whose
    non-blocking `subscribe(stream_id, session_id)` asks for a
    `karyos:ipc` required reader of that exact target and returns it
    once the client's polls have the grant. Asking for another target
    withdraws the previous one: a grant that comes after, or one never
    taken, is released by the client, as is anything left when the
    subscriber drops. A grant that comes while one is held is released
    too, never put over it. A refused request (the target not there
    yet) is asked again on the next call.
  - karyos-archive implements `ReplayTargets` for it, so an
    `ArchiveClient` can be built from one facade client alone:
    `ArchiveConnection`'s transports and `client.replay_targets()`.

- `karyos-catalog list DIR [--json]` (SPEC §11; H4a): an archive directory's
  recordings, read offline through the new `karyos_archive::catalog::list`,
  which never writes. It leaves a compaction's leftover file and does not cut a
  torn last record: it lists up to it and reports the listing as maybe behind
  (an Archive appending, or a crash its next open cuts), never as an error. A
  directory with no catalog lists nothing; a damaged catalog, another format
  version or a missing directory exit 2.
- `karyos-catalog list --live DIR=REQ,RESP [--timeout-ms N] [--json]` (H4b): a
  running Archive's recordings, listed over its control streams on the driver in
  DIR with a `RecordingLister` (Linux), each still recording with the position
  written so far, or where and why it stopped. The connection is opened for the
  listing and closed after it, so it holds none of the Archive's requester
  slots; `--timeout-ms` bounds the wait for the driver and then for the whole
  listing (default 5 s). An Archive that cannot be reached, or refuses, exits 2.
  `karyos_tools::catalog::list_live` is the same listing over any facade client;
  `ListArgs` names its source (`Source::Offline` or `Source::Live`).
  `tests/karyosd_catalog.rs` lists a `karyosd --archive` recording live and
  offline beside it, then offline once the daemon stopped.
- `karyos-replay` (SPEC §11; H5), the replay and output diff binary:
  `karyos-replay diff` is the recording group journal diff, and
  `karyos-tools replay diff` stays as its alias, running the same code
  (`replay::run_diff`, with the usage text named after the command it came
  through). Replaying into a stream is H6's `karyos-replay start`.
- Subscription options over the C ABI (F7b-1): `karyos_subscription_options`
  (`role`: `KARYOS_ROLE_REQUIRED`, `_OPTIONAL`, `_OBSERVER`; `rejoin`:
  `KARYOS_REJOIN_AT_HEAD`, `_CLOSE`; read by prefix, 16 bytes in 0.1.0),
  `karyos_subscription_options_init` and `karyos_client_add_subscription_with`,
  over `Client::add_subscription_with`. An unknown role or policy, or a nonzero
  `reserved`, is `KARYOS_E_INVALID_ARGUMENT` with nothing opened;
  `ClientError::InvalidOptions` maps to it too. Snapshot and replay policies are
  not yet in the C ABI and keep the next codes.
- `karyos_subscription_poll` reports a `karyos:ipc` subscription's end,
  after the messages before it and on every later poll:
  `KARYOS_E_CLOSED_BY_OVERRUN` once its rejoin policy closed it,
  `KARYOS_E_CLOSED` once its stream's seal is reached or it was revoked.
  An overrun it rejoined after, an aborted block or a skip stays
  `KARYOS_OK`; a `karyos:udp` subscription's images end one by one and
  its poll stays `KARYOS_OK`. Until now these stops answered `KARYOS_OK`
  with nothing delivered (an F4 gap, unreachable before a policy could
  close a subscription).
- Conformance: `struct.size.subscription.options` and
  `subscription.options.typed.statuses`, and the runner's
  `karyos_client_add_subscription_with` and `karyos_subscription_close`.
- `Client::add_subscription_with(uri, stream_id, SubscriptionOptions)` (F7b):
  the reader's role (`SubscriberRole::{Required, Optional, Observer}`) and
  rejoin policy (`RejoinPolicy`), which the facade fixed to required and
  rejoin-at-head. `SubscriptionOptions` is `#[non_exhaustive]`, built with
  `new(role, rejoin)`; its `Default` is `add_subscription`'s behaviour, which
  `add_subscription` now delegates to. Each image of a network subscription
  takes the role and a copy of the policy, so a snapshot policy (one stream's
  source) is refused on a `karyos:udp` URI with the new
  `ClientError::InvalidOptions` before anything is requested. The facade
  re-exports `SubscriptionOptions`, `SubscriberRole`, `RejoinPolicy`,
  `Secondary` and `SnapshotSource`.
- The C ABI's Archive-backed rejoin (F9b). `karyos_subscription_options` grows
  to 40 bytes (16 still accepted, sizes between refused) with `archive`,
  `archive_client_id`, `replay_stream_id` and `secondary`, for the new policy
  `KARYOS_REJOIN_ARCHIVE`: an overrun's gap is recovered from the Archive
  handle's recording and merged back into the live stream, with `secondary`
  (`KARYOS_REJOIN_AT_HEAD` or `KARYOS_REJOIN_CLOSE`) after a failed merge. The
  Archive handle lends its control streams and an id; each rejoin takes its own
  request publication and response subscription, released by their drop at the
  subscription's close. An `archive_client_id` of 0 lets the library assign the
  id. `karyos_subscription_rejoin_state` writes a sized
  `karyos_subscription_rejoin` (recovering, and the last failure's
  `KARYOS_MERGE_*` code, `KARYOS_MERGE_OTHER` for one the ABI does not name).
  The poll is unchanged. The conformance runner takes the Archive fields.
- The C ABI lists an Archive's catalog (F9a). `karyos_archive_connect(client,
  options, archive, detail)` opens a connection over the control streams
  `karyos_archive_options` names (`requests`, `responses`, a `client_id` of at
  most 32 bits, a `deadline_ns`); the connection is its client's, which closes
  it. `karyos_archive_list(archive, after_id, limit, handler, context,
  delivered, detail)` is a control call: it waits for the page of at most
  `limit` recordings after `after_id`, then hands each to the
  `karyos_recording_handler` in id order as a `karyos_recording` (state,
  `KARYOS_STOP_*` reason, position, start time in nanoseconds since the Archive
  agent started, and the channel's bytes). Fewer than `limit` ends the catalog.
  A page that does not arrive in time is `KARYOS_E_TIMEOUT`, and an Archive's
  refusal `KARYOS_E_REFUSED` with its response code in the detail.
  `karyos_archive_close` removes the connection's streams from its client.
  karyos-archive's `RecordingLister::start_from(from_id, count)` begins such a
  bounded listing, whose pages ask for no more than are left to keep. The
  conformance format gains the three calls, with the scenario
  `archive.typed.statuses`.
- The C ABI's scheduled offer (F7a-3): `karyos_publication_offer_at(publication,
  lane, data, length, tx_time, accepted)` offers on a timed lane at its
  requested time, with `KARYOS_E_INVALID_SCHEDULE` for a lane that is not timed,
  a time below the lane's last, one past its horizon or an overflowing deadline;
  and `karyos_clock_now(domain, now)` with `KARYOS_CLOCK_MONOTONIC` and
  `KARYOS_CLOCK_TAI`, the time it expects, which callers read on every platform
  (on macOS the monotonic domain has a per-process origin). An unknown domain is
  `KARYOS_E_INVALID_ARGUMENT`, and `CLOCK_TAI` off Linux `KARYOS_E_UNSUPPORTED`.
  The conformance format gains both calls and the `schedule_capacity` argument
  of `karyos_driver_add_stream`, with the scenario `publication.timed.offer`.
- `karyosd` runs the Archive (H3). `--archive DIR` starts the agent with its
  catalog in `DIR`, and `--archive-control REQ,RESP` names the control streams,
  which the daemon adds (REQ concurrent). `--record id:session[:sync]`
  (repeatable; sync `none`, `segment` or a duration) starts a recording at boot
  through the control path, and a shutdown stops it, then the agent.
  `--archive-min-free` (default 1 GiB) refuses a recording while the archive's
  file system has less free space, measured by the new
  `karyos_sys::fs::free_bytes` (Linux). Under same-uid admission every admitted
  client may control the Archive: the trust boundary is the daemon's uid, and
  per-client authorization comes later. The audit trail (target
  `karyos::archive::audit`) names each grant on the control streams, each
  request and each answer, through the driver's new
  `EmbeddedDriver::audit_grants` and `drain_grant_audits`.

- `Publication::offer_at_on(lane, payload, tx_time)` on the client facade: a
  timed offer on one lane of a publication, checked by the lane's handle before
  anything is reserved.

- The C ABI conformance suite covers more of SPEC.md §13's C ABI boundary row
  (F6; `crates/karyos-ffi/conformance/`): a closed publication and a closed or
  ended claim answer `KARYOS_E_CLOSED` (`publication.use.after.close`,
  `claim.use.after.close`, `claim.double.commit`); one claim per publication; a
  claim's typed refusals and an offer with no subscriber
  (`publication.typed.statuses`); and the struct size rule of both minor
  directions for the driver, stream and client options and `karyos_detail`
  (`struct.size.*`), and a nonzero `reserved` in the driver options refused
  (`struct.reserved.driver.options`). The interim format 1 gains the driver's
  thread and streams, the publication and claim calls, and sized structs whose
  unset bytes hold a sentinel, so a write past a struct is seen. A runner that
  meets a function or argument it does not know fails the scenario.
- `make libkaryos` packages the C ABI for the language bindings (B1) into
  `LIBKARYOS_DIR`, by default `target/libkaryos`: `include/karyos.h`,
  `lib/libkaryos.a`, the shared library (`libkaryos.so.0.1` on Linux,
  `@rpath/libkaryos.0.1.dylib` with compatibility version 0.1 on macOS:
  MAJOR.MINOR of the ABI before 1.0), a relocatable `lib/pkgconfig/karyos.pc`,
  the conformance suite's format, index and scenarios, a `MANIFEST` of the ABI,
  protocol and core versions, commit and build, and `LICENSE.md`. The script
  (`scripts/package-libkaryos.sh`) compiles no C. It checks that the shared
  library exports exactly the functions the header declares, that the static
  library defines them, the soname or install name, no RPATH, RUNPATH or
  LC_RPATH, and the `.pc` where `pkg-config` is installed. It builds for the
  host only, marks a dirty tree in the MANIFEST and refuses one under
  `KARYOS_PACKAGE_REQUIRE_CLEAN=1`. Not part of `make pre-push`.
- Subscriptions over the C ABI (F4; ADR-0067): `karyos_client_add_subscription`,
  `karyos_subscription_poll` (a `karyos_message_handler` callback, a
  `MessageLimit` as `limit`, the count delivered also on failure),
  `karyos_subscription_next_image_change`,
  `karyos_subscription_image_changes_lost` and `karyos_subscription_close`, with
  `karyos_message_info`, `karyos_image_change` and `KARYOS_MAX_SUBSCRIPTIONS`.
  Each message reaches the handler from a private copy owned by `libkaryos`,
  never a term or a shared mapping: allocated at the add with the largest
  message the subscription can deliver, grown only when a newly adopted image or
  mapping has a larger one (`KARYOS_E_SYSTEM`, before anything is delivered,
  when it cannot). The handler runs with the subscription held, so reentering it
  or closing its client returns `KARYOS_E_REENTRANT`, and another thread gets
  `KARYOS_E_BUSY`. A client's close takes every publication and subscription
  before it closes any. The header checker reads callback typedefs. A
  publication or subscription whose handle a panic poisoned is now closed by its
  close (`karyos_publication_close` answered `KARYOS_E_INTERNAL` and kept it).

- A remote client binds a guarded exclusive publication (G-x3).
  `RemoteClient::take_publication` maps the grant's outcome ring and guard words
  read-only and its consumed cell writable, reads the guard's index and
  admission epoch from the ring's header, and binds the handle: it is gated by
  the guard word it was granted and reads its outcome records with
  `poll_outcomes`. Each binding region holds its own export, detached when the
  handle drops, never at a mapping cutover. The control path now issues guarded
  publications to remote clients; clients of the in-process command ring and
  timed lanes are still refused (`InvalidPublicationMode`). The facade's
  `Publication` gains `poll_outcomes_on(lane, limit, handler)`.
- The driver grants a guarded exclusive publication's binding over the control
  path (G-x2), behind a test-only switch: the control path still refuses guarded
  streams until the client binds the regions (G-x3). The grant carries, under
  one key, the log buffer, then the handle's outcome ring (driver-only), its
  consumed cell (writable by its client alone) and the guard region
  (driver-only), each its own export and ledger entry, checked against
  `max_exports_per_client` and the fetch bounds before anything is reserved.
  Every guard's word now lives in one array of `max_guards` words, a driver-only
  region in IPC mode; a guard's index is never reused, and the ring's header
  names it. The walker's bound holds the ring and the cell until its last
  outcome record, after the handle or its grants are gone. Concurrent guarded
  publications follow when GC-7 lifts. The admission manifest rule changes in
  place under the unreleased version 2: a guarded grant's manifest lists exactly
  `OutcomeRing`, `ConsumedCell`, `GuardRegion` after its log buffer records and
  carries a base; the binding's kinds appear in no other manifest.
  `outcome_ring::init` also zeroes the reserved header words (#501).
- The guard binding's region kinds and outcome header (G-x1). `RegionKind` gains
  `GuardRegion` (12), `OutcomeRing` (13) and `ConsumedCell` (14), with the same
  codes in `karyos-sys` and on the wire, under the unreleased admission version
  2; no grant carries them yet, and the control path still refuses guarded
  streams. The outcome ring's layout version moves to 2 (unreleased):
  `outcome_ring::init` takes a `Binding` and writes `C_m`, `C_r`, the guard's
  word index and the admission epoch in header words 2 to 5, and
  `outcome_ring::binding` reads them back for a client, refusing a slot count
  other than `C_m + C_r + 1`, an index past the client's guard words, or an
  epoch that is not open.

- karyos-client's `Subscription` gains `adopt()`, `max_message_length()` and
  `poll_adopted(handler, limit)`, so a caller can size a copy of each message
  before it polls. `adopt` takes the images a network subscription's client has
  attached or retired, and moves every handle a previous `poll_adopted` left at
  a mapping's seal to its successor; `max_message_length` is the largest message
  of the stream, or of the adopted images, and changes only at an adoption;
  `poll_adopted` is the same poll that never adopts and never moves, so an image
  or a successor offered meanwhile waits for the next adoption, and a handle
  stopped at a seal sets the new `stopped_at_seal` of `SubscriptionPoll` and
  `PollSummary`. `poll` is unchanged: it adopts, and moves within the poll. The
  C ABI's subscription poll (F4) builds on it.

- `Client::remove_concurrent_publication`, the removal matching
  `Client::add_concurrent_publication` (#484): the driver frees the handle's
  publisher slot when it serves it, so the stream's `publishers` bound counts it
  no more. A removal that cannot be sent drops the handle and counts in
  `publication_releases_failed`. `RemoteClient` gains
  `remove_concurrent_publication`, and `Connection` a hidden
  `release_concurrent_publication`. Needed by the C ABI's concurrent
  publications (F7a-1).

- A journal that cannot be opened at the agent's start raises the `journal_gap`
  alert (karyos#497). The view shows its unknown interval with reason
  `journal_unavailable_at_start` (code 5) at position `u64::MAX` until an
  administrator acknowledges it with `gap-ack`. With no journal to record it,
  the interval and its acknowledgement are held in memory only, the
  acknowledgement logged at info on standard error with the uid and the
  interval, and the next start raises it again while the journal still cannot be
  opened.
- The operations journal records how each agent run ends (a follow-up of M10b):
  `agent started` (kind 8) is written durably when the journal opens and
  `agent stopped` (kind 7) by `Agent::stop` / `Journal::stop`, the agent's one
  clean stop. A start whose journal does not end with a clean stop records an
  unknown interval, so a guard close made while the journal was down and lost in
  a crash is never silent. Each unknown interval carries its reason
  (`GapReason`, the record's code, and `reason` in API v1's `gap`):
  `request_without_outcome`, `torn_tail`, `unclean_stop` or `journal_replaced`,
  so an administrator tells a crash from a lost operation before acknowledging
  it. Until karyos-agent may catch signals, a signal stop of the binary is
  recorded as an unclean stop.

- `karyos_archive::agent::RecordedFrom { Local, Image }` (karyos#490b; D2-2):
  what a recording reads, as its host knows it. `HostRecording::with_origin` and
  `StartRecording::with_origin` set it; `new` means `Local`, so existing hosts
  are unchanged. A host recording its own `karyos:udp` publication beside that
  publication's loopback image has two recordings of one stream, session and
  lane, with the same channel and source incarnation:
  `ArchiveHandle::recording_word` now answers the local stream's recording
  first, and an image's only when it is the one recorded, never a silent pick.
  It is not kept in the catalog, as the word is live only. A Gateway's network
  subscription beside a local source of its stream stays refused,
  `DuplicateSource`, in either order.

- Per-stream network counters in the CnC (phase 5, M2b). Each network
  publication has `network frames sent`, `network bytes sent`,
  `network retransmits` and `network naks received`, and each exposed image
  `network naks sent`, `network losses` and `network repaired`, keyed by the
  stream's registration; `karyos-stat` and the agent show them with no change.
  The owning agent stores its own counts at the end of its duty cycle, so no
  atomic is added per datagram. The cells are allocated all or none (when the
  region is full, `counters unavailable` counts one and the stream runs without
  them, never retried) and freed when the publication is removed, the image
  retires or the network closes. Size `counters_capacity` for 4 cells per
  publication and 3 per image.

- `karyosd`'s startup capability log (SPEC §11, "logged at startup"; M3b). With
  the network on, the daemon reads its own CnC at most every 250 ms
  (`daemon::CAPABILITY_CHECK`) and logs each network endpoint's capability
  gauges (M3) at info, once when the endpoint first appears and again at each
  new capability epoch: `endpoint capabilities` with the endpoint, the epoch and
  `capabilities`, one field per gauge naming the capability and its state, with
  its reason and detail (`gso=unavailable(library_api)`,
  `send_buffer=fallback(below_request, 212992)`).
  `karyos_tools::capability_log::line` formats it; a code or gauge it does not
  know is kept by number.

- `karyosd --network <on|off>` (off by default): `on` runs the driver's network
  agents with `NetworkConfig::default()` (dedicated threads), so clients create
  `karyos:udp` publications and subscriptions by URI, whose `term-length`, `mtu`
  and `lanes` keys override the stream defaults; the start log says whether the
  network runs. The rest of the network configuration is not on the command line
  yet: the agents' rings and session limits, the threading mode, the image
  template, the stream defaults, the NAK control groups and the per-client
  limit. Tested end to end through two `karyosd` processes on loopback.

- Guard operations through the management agent (M10b2). The agent's socket
  takes `guard-close DIR GUARD [REASON]`,
  `guard-reopen DIR GUARD EPOCH [REASON]` (the reason is the rest of the line)
  and `gap-ack POSITION`, bounded by the interim role matrix: operators and risk
  officers close, risk officers and administrators reopen, administrators
  acknowledge; any other request of a role is `forbidden`. The agent attaches to
  the driver as a client for the one command, for the peer's uid as the
  operator, and journals a request record before and an outcome record after
  (`karyos_agent::operations`). A close goes ahead whether its record was
  written; a reopen is refused (`journal unavailable`) unless its record is
  durable first, and without a journal (`karyos-agent --journal DIR`,
  `AgentConfig::with_journal`). API v1's view appends `journal`: its recording,
  `unsealed`, whether it is unavailable and why, its failed appends, the open
  unknown interval and its `journal_gap` alert, raised also from a failed append
  until the agent restarts (`Journal::failed_at`). `Server::poll` takes the
  agent mutably.

- The management agent lists a driver's Archive catalog (phase 5, M11).
  `karyos-agent --archive DIR=REQ,RESP` (`AgentConfig::with_archive`,
  `karyos_agent::catalog::CatalogConfig`), off by default, names a watched
  driver and its host's Archive control streams. A thread per such driver
  connects as an IPC client with a short timeout, takes a concurrent handle on
  the request stream (which the host configures concurrent) and subscribes the
  response stream, lists the catalog with `RecordingLister` within a deadline
  and lists again after an interval; failures are counted and retried.
  `DriverView::catalog` (API v1, after `alerts`) holds the last complete
  listing, `left_out`, `listed_at`, `listings`, `failures` and `last_error`; the
  exporter adds `karyos_archive_recordings`, `karyos_archive_listings_total`,
  `karyos_archive_listing_failures_total` and `karyos_archive_listed_at_ns`. It
  costs one client slot of that driver. The crate graph test checks that
  karyos-archive never depends on the agent.
- The agent's catalog thread (M11) ends its session as soon as the agent's
  refresh finds the driver closed, counting it ("the driver closed") instead of
  waiting out the listing deadline; a refusal is tested to be counted and
  followed by a listing on the same connection (#488).

- The management agent's operations journal (M10b, interim).
  `karyos_agent::journal::Journal` keeps the guard operations as one `required`
  Archive recording on channel `karyos:operations-journal` in a journal
  directory, resumed at start, recorded through the Archive's `Recorder` from
  the new `karyos_archive::queue::QueueSource`, which lays queued records out as
  the DATA frames of a log (padding a term's end). Each record is version 1:
  kind, host time, guard, expected epoch, operation, operator, parameters
  digest, outcome code, guard word and up to 128 bytes of reason.
  `append_durable` returns only once the record is durable (a reopen fails
  closed without it); an append that fails leaves the journal unavailable and
  counts in `failed_appends`. At start, a request with no outcome after it, a
  tail recovery cut, or a journal recording stopped by another hand records an
  unknown interval, which stays open across restarts until `acknowledge_gap`
  records an administrator's acknowledgement of it. `Recorder::sync` and
  `Recorder::source_mut` support it. The agent's requests, roles and alert
  follow.

- `Client::add_concurrent_publication(uri, stream_id)` in karyos-client
  (M11): a concurrent handle on lane 0 of the only `karyos:ipc` stream of
  the id, shared with its other publishers, as the Archive's request
  stream is by its requesters. The CnC command `AddNetworkPublication`
  (0x0F) gains flag bit 1, concurrent, in place under admission
  `VERSION` 2; a driver that does not know the bit retires the client as
  faulty (`ClientProtocolViolation`).
  The driver refuses an exclusive stream with `InvalidPublicationMode`
  and a `karyos:udp` channel with `UnsupportedChannel`.

- The management agent's guard pending-acknowledgement alert (M4b's follow-up to
  M9). At every refresh the agent reads each guard's close acknowledgement
  (`karyos_client::guard_acks`): a close in effect with senders overdue, in a
  consistent read, fires `AlertKind::GuardAck` (JSON `"guard_ack"`, the
  Prometheus `kind` label likewise), its `participant` the guard id and its
  `value` the senders overdue. It clears when a consistent read shows none
  overdue, the guard is gone or a refresh reads nothing; a read that may mix
  passes changes nothing, and a new close of the guard starts it over. The
  driver's `guard_ack_timeout` is the bound: the rule has no option of its own.

- Guard close and reopen for a client (M10):
  `ClientConductor::guard_close(guard, operation, operator, reason)` and
  `guard_reopen(guard, expected, operation, operator, reason)`, and the same on
  `RemoteClient`, complete as `Outcome::GuardState { guard, state }` or are
  refused as the driver documents. They compute the parameters digest from the
  request; a reopen naming an epoch that cannot be closed is refused before
  submission (`ConductorError::InvalidGuardEpoch`).

- Guard close acknowledgements for tools (M4b). While a guard is closed by a
  close, the conductor counts that close's registered senders as
  `close_guard_ack` reports them, at every duty cycle and without allocating:
  `guard senders applied`, `guard senders in flight`, `guard senders pending`
  and `guard senders overdue`, with `guard ack epoch` (0 while no close is in
  effect), gauges keyed by `KIND_GUARD` and the guard id, written inside a pass
  on `guard ack pass` and allocated all together or not at all.
  `karyos_client::guard_acks::guard_acks` reads them, and
  `karyos_client::groups::read_groups` reads any such group (`capabilities` now
  uses it). A guard may not be named after one of the six labels, as its word
  gauge shares their keys (`InvalidConfig`).

- karyos-archive's recording lister (phase 5, M11):
  `client::list::RecordingLister` reads the whole catalog over the control
  streams, page by page, never blocking. A page that delivered any recording
  asks for the next one from the id after its last, since the Archive leaves out
  a recording it cannot describe; the listing ends at an empty page or a
  refusal. It keeps at most `ListerConfig::max_recordings` and counts the rest;
  answers to other requesters are skipped. The management agent's catalog view
  builds on it.

- API v1's JSON carries each driver's trace window (M6c): `latencies`, one
  object per lane with `p50`, `p90`, `p99`, `p999` and `max` as `null` or
  `{"low","high"}` bounds, and `trace`, the window's counts. They come after
  `guards` and before `alerts`, in `DriverView`'s declaration order.

- The Prometheus exporter (phase 5, M8; ADR-0055; SPEC.md §11
  `karyos-exporter`). `karyos_agent::exporter` renders an `AgentView` in the
  Prometheus text format (0.0.4): the CnC cells by type (events and spin time as
  counters, gauges, positions and timestamps as gauges), lane positions,
  headroom and subscriber lag, ring read and overwrite counts, error occurrences
  by code, and the trace window's latency quantile bounds and counts. It answers
  `GET /metrics` only, on a loopback address only, at most 16 connections per
  poll, with 100 ms I/O timeouts. The `karyos-exporter` binary, in karyos-agent,
  runs it as its own process: `--listen ADDRESS:PORT --driver DIR...
  [--refresh-ms MS]`; a non-loopback address is refused. No TLS, no
  authentication and no new dependency. It exports M9's alerts as
  `karyos_alerts_firing` per driver and each alert's `karyos_alert_value` and
  `karyos_alert_since_ns`, and takes one of each driver's tool slots while
  attached.

- Alerts in the management agent (M9). `AlertRules` (`AgentConfig::with_alerts`;
  `karyos-agent --lag-bytes --lag-refreshes --loss-quiet`) are evaluated at
  every refresh: a subscriber lagging `lag_bytes` or more over `lag_refreshes`
  consecutive consistent samples (8 MiB and 3 by default; a mixed sample changes
  nothing), and a loss report that grew (read or overwritten), cleared after
  `loss_quiet` refreshes without a new loss (10). `DriverView::alerts` (`Alert`,
  `AlertKind::{Lag, Loss}`) lists those firing, with the time each began; API
  v1's JSON appends `alerts` to each driver. The agent's command line refuses a
  uid given two roles, and one poll serves at most 16 connections
  (`server::MAX_ACCEPTS`). The guard pending-acknowledgement rule follows M4b.

- The management agent's trace latency window (phase 5, M6c). Per driver, a
  follower of the trace mirror pairs each `Publish` with its `SubscriberPoll`s
  and keeps per publication lane the observed latencies of the last window of
  the agent's time (`DriverView::latencies`, `LaneLatency` with p50, p90, p99,
  p99.9 and max as intervals), under the trace report's automatic calibration
  rule; never trace verdicts. Journals, pending messages, polls and lanes are
  bounded by `WindowConfig`, and what a bound refuses, ages out or the mirror
  overwrites is counted (`TraceCounts`). karyos-agent now depends on
  karyos-trace.
- The management agent's local API v1 (M7; no new dependency).
  `karyos_agent::json` writes API v1 by hand (fields under their Rust names in
  declaration order, exact integers, the instance as 32 hex digits, `null` for
  none); `karyos_agent::server` serves it on `<api-dir>/agent.sock` (a private
  `0700` directory, the socket `0600`; a stale socket replaced, a live one
  never) to the uids of a role table (`Role`: viewer, operator, risk officer,
  administrator), checking the peer's uid (`SO_PEERCRED`). One request line per
  connection, `KARYOS-AGENT 1 view`, one JSON answer; another version is
  answered with the versions supported, a uid without a role `not authorized`.
  The `karyos-agent` binary runs it (`--api-dir`, `--driver`, `--role UID=ROLE`,
  `--refresh-ms`). The API compatibility test pins API v1's JSON field for
  field.

- Consistent reads of an endpoint's capability gauges (M6b): the conductor
  writes each endpoint's gauges inside a sampling pass on a new
  `capability pass` cell (same keys; odd while it writes, even after, with the
  `begin_pass`/`end_pass` fences), and `karyos_client::capabilities::
  endpoint_capabilities` reads each group with `read_pass`, for tools and the
  management agent alike, marking it inconsistent when every attempt overlapped
  a write. The guard audit ring's losses are counted:
  `guard audit records overwritten` and `guard audit records dropped` (sequences
  exhausted).

- The management agent's core, `karyos-agent` (phase 5, M6a; ADR-0055). `Agent`
  attaches to each configured driver as a tool, counting against its
  `max_tools`, and keeps a model per driver: whether it is attached, closed or
  unavailable; one sampling pass of the driver counters, with per stream lane
  the limit, head, floor, headroom and each subscriber's lag; the client
  counters; and followers of the error log, the loss report and the guard audit
  ring with their cursors, a bounded history and the records overwritten before
  they were read. `api` defines API v1 as Rust types (`AgentView`), with no
  transport yet (M7). Trace histograms (M6c) and capability groups (M6b) follow.
  The crate graph keeps the driver and the client independent of it.

- Spin time per idle loop (counter type 3, `TYPE_SPIN_TIME`; SPEC §11; M5).
  `karyos_driver::spin::SpinMeter` measures per spin run, two host clock reads a
  run and never on the wake path, flushing every 1024 spins for a loop that
  spins without end, into one driver-wide cell per idle loop:
  `conductor spin time`, a fixed counter the driver keeps and copies from the
  meter's shared word at each duty cycle (the meter goes to the loop that drives
  `do_work` with `EmbeddedDriver::take_spin_meter`; `karyosd`'s `BackoffIdle`
  reports it), and per agent loop `sender spin time` and `receiver spin time`
  (Dedicated) or `network spin time` (SharedNetwork), keyed cells their meters
  own and alone write. `IdleStrategy::attach_spin_meter` hands a loop its meter;
  the default `YieldThenSleep` never spins and reports 0. `BackoffIdle` is no
  longer `Clone`.

- The session table in snapshots (phase 4, C7/C8 glue).
  `SessionTable::encode` writes the table as a snapshot's sessions section
  (`dedup::SESSIONS_VERSION`), and `SessionTable::decode` rebuilds it, with
  the log time, the last registration's index (`registered`) and every live
  session's slot, client, epoch, activity, window and retained replies;
  decoding checks every bound (`DecodeError`). A decoded table answers
  every later entry as the encoded one and encodes to the same bytes.
  karyos-sim's `tests/dedup.rs` snapshots a replica through C8a's store on
  the simulated disk, crashes a third of the writes, rebuilds the replica
  from what survived plus the log, and checks it under C3.
- Guards for tools and the management agent (M4). Every guard transition,
  refusals included, is also appended to a guard audit ring
  (`karyos_sys::diag::GuardAudit`, `GuardAuditRecord`, 16-word records with host
  `CLOCK_MONOTONIC` and driver times, guard, words before and after, operation
  id, requester and outcome), a driver-only region of the new kind `GuardAudit`
  (code 11 on both sides) that a tool receives as the sixth `ToolAdmitted`
  record, in place under admission version 2 (unreleased);
  `RemoteTool::guard_audit` and `EmbeddedDriver::guard_audit_ring` read it. Each
  guard's word is a gauge labelled with its name, keyed by the new participant
  kind `KIND_GUARD` (5) and the guard id.
- Each network endpoint's effective capabilities in the CnC, for tools and the
  management agent (SPEC §16.8; M3): one gauge per capability field
  (`capability epoch`, platform, copy mode, queue assignment, max datagram,
  observation points, clock granularity, each capability's state with its reason
  and detail, and the effective buffer sizes), keyed by the new participant kind
  `KIND_ENDPOINT` (4) and the endpoint's instance id, rewritten at each reopen
  and freed when the endpoint leaves or the network closes. The driver-wide
  events `capability fallback` (capabilities on a fallback, once per endpoint
  epoch) and `capability missing` (opens and reopens refused for a required
  capability) count degradations.

- Streaming snapshot reads in karyos-cluster (C8a follow-up, #463).
  `SnapshotStore::reader` returns a `SnapshotReader` that hands out sections
  (`SectionHeader`) and their bytes in the caller's buffer, checking the digest
  at the end; `SnapshotStore::verify` streams the same check, and `open` uses it
  instead of loading each snapshot whole. A section's bytes go to A2 in writes
  of at most `WRITE_CHUNK` (64 KiB), so A2's recovery scan of a snapshot is
  bounded too.

- Prefix purge of the Raft log (phase 4, C8b). A2's
  `SegmentStore::purge_before` moves a recording's start forward to a write
  boundary and removes the whole segments below it. The new start, the
  floor, is replaced atomically in `<recording>.floor` before anything is
  removed, and recovery starts the recording at the floor
  (`DropReason::Purged`; `SegmentError::InvalidPurge`, `FloorDamaged`,
  `FloorMissing`). karyos-cluster's `RaftLog::purge_prefix(below)` now
  purges committed entries and returns the new first index, instead of
  `LogError::PurgeUnsupported` (replaced by `PurgeBeyondCommit`). If a
  crash leaves the first-index file stale, `RaftLog::open` follows the first
  frame. karyos-sim's `tests/purge_crash.rs` crashes the disk at every
  operation of two purges and fails every flush.

- karyos-sim harness: a standby cluster, phase 5 batch P5-S2 (H3 and H4;
  ADR-0054). `Case::standby` adds a second group of servers fed by the primary's
  leader with its committed entries (`harness::standby`: each entry checksummed
  over its index, term and payload, resent from the standby's acknowledged
  verified position, `FeedFault`s for one send), which the standby's leader
  checks by log matching and checksum and proposes, its service applying them
  with effects disabled. Fencing is `Action::OperatorStop` or an `ExternalLease`
  (`Case::lease`, `Action::CutArbiter`) that the primary's leader must hold to
  take a command or release a reply; `Action::Promote` raises the generation
  once the harness verifies the fencing, the standby reporting its verified
  position, learnt commit and the requests in flight, and redirects the clients.
  Replies and successes carry a generation, and a client rejects a lower one.
  The reference fixture's leader is the lowest of its bootstrap peers, so a
  standby leads itself. New checks: `check::group` per group of servers,
  `check::standby` (no standby reply before a promotion, no primary reply at or
  after the fencing point (the lease's end on the holder's clock, recorded with
  `Fenced`, or the operator's stop), no old-generation reply after it, every fed
  entry the primary's, the verified prefix applied, the gap report bounded, no
  client going back a generation) and `check::across_promotion`, which leaves an
  old-generation answer above the verified position pending for C3. Scenarios S1
  to S4, S6 and S7 run on the reference; S5 is a client test.

- `karyos-ffi`, the C ABI crate (SPEC.md §10.2; ADR-0053, ADR-0067; batch F1).
  It builds `libkaryos_ffi` as a shared, a static and a Rust library, with a
  hand-written `include/karyos.h` that a test checks against the Rust source
  until `cbindgen` is admitted. F1 exports `karyos_abi_version` (ABI 0.1.0) and
  `karyos_status_message`, and defines the status codes, grouped by range and
  mapped from the client's Rust errors, the bounded tables of generation-tagged
  handles (a per-slot `try_lock`, so a call never blocks: `KARYOS_E_BUSY` from
  another thread, `KARYOS_E_REENTRANT` from the same one, `KARYOS_E_INTERNAL`
  after a panic poisoned the slot; a slot whose generation cannot grow is
  retired) and the panic boundary. `unsafe` is denied in the crate and expected
  only on `mod abi` and in the tests' `support::abi`; `make lint-sync` checks
  that, the clippy set, and that no profile sets `panic = "abort"`. `make miri`
  also runs the crate's tests.
- `karyos-ffi` publications and staged claims (batch F3):
  `karyos_client_add_publication` (`karyos:ipc` or `karyos:udp`),
  `karyos_publication_offer` on a lane, and the staged claim
  `karyos_publication_claim`, `karyos_claim_commit` and `karyos_claim_abort`,
  with `karyos_publication_close` and the sized `karyos_accepted`. A claim's
  buffer belongs to `karyos-ffi`, never a term or a shared mapping; the commit
  claims in the term, copies and commits in one call. A commit that meets back
  pressure, no subscriber, an administrative action, the rate limit or a closed
  guard keeps the claim staged for a retry; one claim per publication
  (`KARYOS_E_CLAIM_OUTSTANDING`). Closing a client closes its publications and
  their claims, all or nothing: while one is in use nothing closes. Tests over
  an embedded driver run under Miri and on macOS.
- `karyos-ffi` concurrent publications (batch F7a-1):
  `karyos_client_add_concurrent_publication` takes a concurrent handle on
  lane 0 of a `karyos:ipc` stream the driver configures for concurrent
  publishers. The offer, claim, commit, abort and close calls apply to it
  as to an exclusive publication; any other lane is `KARYOS_E_INVALID_LANE`.
  Closing the handle frees its publisher slot in the driver. Guarded and
  timed lanes stay out of scope until the driver grants them across
  processes (F7a-2).
- `karyos-ffi` handle tables: a stale handle no longer touches its slot's
  mutex. Its slot's generation is now an atomic checked first, and a close
  moves it on at once, so a stale handle answers `KARYOS_E_CLOSED` and
  never makes a live handle's call on another thread answer
  `KARYOS_E_BUSY` (seen as a flake when the tests share the tables).
- `karyos-ffi` clients (batch F2): `karyos_client_options_init`,
  `karyos_client_connect`, `karyos_client_poll` and `karyos_client_close`,
  with the sized `karyos_client_options` (copied, nothing consumed) and
  `karyos_detail` structs. A driver that refuses the client's protocol
  version, or admits it at another, answers `KARYOS_E_INCOMPATIBLE_DRIVER`
  with the driver's version in the detail when it named one; tested on
  Linux against a fake driver, and a real one for the admitted path. The
  client tests also run over an embedded driver's conductor, under Miri
  and on macOS, where connect answers the new `KARYOS_E_UNSUPPORTED`. The
  header check now covers structs.
- The C ABI conformance suite beside `karyos-ffi` (ADR-0067; batch F6), in the
  interim format 1 of `crates/karyos-ffi/conformance/FORMAT.md`: line-based
  `.kcs` scenarios (`call` and `expect` steps, status names read from the
  header, variables, an `abi` version that a runner checks against
  `karyos_abi_version`), and `index.txt`, which maps the §13 C ABI rows to
  scenarios or to the batch that brings them. The Rust runner
  (`tests/conformance.rs`) runs every scenario through the exported symbols and
  checks the map. First scenarios: the ABI version, null out-parameters and
  status texts.
- `karyos-ffi` embedded drivers (batch F5): `karyos_driver_options_init`,
  `karyos_driver_create`, `karyos_driver_do_work` (the caller drives it),
  `karyos_driver_start` and `karyos_driver_stop` (a thread of its own
  drives it under an idle strategy; `KARYOS_E_BUSY` to the caller
  meanwhile), `karyos_driver_add_stream` and `karyos_driver_remove_stream`
  (the sized `karyos_stream_options` with `karyos_stream_options_init`:
  the fields of the Rust `StreamConfig` and its log buffer without
  conflation; lane 0 and exclusive publications only in this version, so
  later minors only widen what is taken; streams are keyed by stream id
  alone, so a second session of one is refused), `karyos_driver_connect` (a
  client in this process over a conductor of the driver) and
  `karyos_driver_close`, with the sized
  `karyos_driver_options` (a subset of `DriverConfig`, the rest its
  defaults; an older header's smaller struct is read by its prefix). A
  client of an embedded driver follows it: `KARYOS_E_INTERNAL` once a
  panic poisoned the driver (in a called duty cycle or on its thread),
  `KARYOS_E_CLOSED` once it is closed, and so do its publications, by
  one load of the driver's state, without its lock. A nonzero `reserved`
  word in `karyos_driver_options` is refused.
  Closing a driver leaves its clients open, to be closed. `KARYOS_MAX_DRIVERS`,
  `KARYOS_PUBLICATION_EXCLUSIVE`, `KARYOS_LOSS_*` and
  `KARYOS_PROTOCOL_VERSION` (asserted at compile time against
  karyos-protocol's) join the header. `karyos-driver` becomes a dependency
  of `karyos-ffi` (SPEC.md §14). The conformance runner gains the driver
  and client calls and variable arguments; new scenarios cover use after
  close, double close and a handle of the wrong kind.
- `karyos-ffi` guarded publications and their outcome streams (batch F7a-2):
  `karyos_client_add_publication` takes a guarded stream's publication for a
  client of a driver in another process, which binds its guard and outcome ring
  (G-x3); an embedded driver's client is refused one with `KARYOS_E_REFUSED`,
  detail code 6 (invalid publication mode), as in Rust.
  `karyos_publication_poll_outcomes` hands up to `limit` records of a lane to a
  `karyos_outcome_handler`, in sequence order, each as a `karyos_outcome` (72
  bytes: its size, a `KARYOS_OUTCOME_*` kind, lane, receiver, sequence,
  incarnation, start, end, epoch, reason and lost) valid for the call; it never
  waits and never allocates. An unguarded lane and lane 0 of a concurrent handle
  have no records. After the final `KARYOS_OUTCOME_OUTCOMES_LOST` record, polls
  deliver 0 and offers and claims return `KARYOS_E_OUTCOMES_LOST`, as the
  facade's do. The handler's calls on its publication are `KARYOS_E_REENTRANT`.
  Tests over an in-process guarded publication run under Miri; a remote client's
  runs end to end on Linux. The guard operator API is not exported.
- karyos-client's `Publication::from_handles`: the facade publication over the
  handles of an in-process driver's stream, lane 0 first, as
  `EmbeddedDriver::publication` returns them. It refuses no handles, lanes out
  of order and handles of different streams, and hands them back; that they are
  of one registration is the caller's duty. A client cannot release such handles
  to their driver: its `remove_publication` drops them and counts them in
  `publication_releases_failed`. Needed by the C ABI's outcome tests under Miri
  (F7a-2).
- `karyos_protocol::cnc::ErrorCode::code` is public: the wire value of a
  refusal code, which the C ABI reports as a detail.
- Client deduplication in karyos-cluster (phase 4, C7a). `dedup::SessionTable`
  is the replicated session table, driven only by applied entries: a bounded
  window of replies per session (`Request` with its lowest unanswered sequence;
  `Outcome::Applied`, `Retained`, `Duplicate`, `WindowFull`, `OutOfOrder`,
  `ReplyTooLarge`), sessions refused when the table is full and never evicted
  (`RegisterError::SessionsExhausted`), session epochs assigned by the
  registering entry's log index (`Registered`), so a late duplicate never
  revives a session, and expiry by log time (`SessionExpired`). All memory is
  allocated at `SessionTable::new`. `DedupConfig`'s defaults (1024 sessions, 64
  replies, 8 KiB, 60 s) are interim values. karyos-sim's `tests/dedup.rs` checks
  retried, duplicated, late and expiring requests with C3's checker.
- Snapshots in karyos-cluster (phase 4, C8a). `snapshot::SnapshotStore` writes a
  snapshot as typed sections (`SectionKind`: consensus, sessions, timers,
  guards, service; each with a version) into its own segment store, syncs it,
  and only then publishes it by replacing the manifest (`snapshot-manifest`: id,
  index, term, length, CRC-32C digest). It keeps the newest
  `SnapshotConfig::keep` and removes the others' files.
  `SnapshotConfig::log_floor` gives the first log index to keep with the
  catch-up allowance, and `due` the entry and byte trigger. Recovery removes
  every store the manifest does not name and reports a published snapshot that
  no longer reads whole. The defaults (keep 2, a 1 GiB allowance, 1 Mi entries,
  256 MiB) are interim values. karyos-sim's `tests/snapshot_crash.rs` crashes
  the disk at every operation and fails every flush.
- The driver's CnC counters for tools and the management agent (M1 and M2). M1:
  `driver pid` (in the driver's own pid namespace), `driver started at` and
  `conductor duty at` (host `CLOCK_MONOTONIC`). M2: the network agents' system
  counters as driver-wide event cells, each written only by its agent at the end
  of its duty cycle in every threading mode: `network controls sent`,
  `network control send failures`, `naks received`, `status messages received`,
  `heartbeats sent`, `datagrams received`, `datagrams dropped by backend`,
  `invalid frames received`, `status messages sent` and
  `images retired at timeout`. Closing the network frees them.

- karyos-sim harness: phase 5 membership scenarios, batch P5-S1 (ADR-0054).
  `ConsensusCore` gains two provided methods, `configuration()` and
  `propose_change()`, whose defaults describe static membership, so a phase 4
  core implements neither; `Configuration`, `Change` and `ChangeRefused`
  describe them. Servers record `Observation::Configuration` at each start and
  after each change, and `Observation::Change` for an operator's change. Cases
  gain `spares` (servers that wait down until `Action::Join`), `Action::Change`
  (sent by an operator node to every server that is up) and `promotion_lag`. The
  reference fixture changes its membership with its fixed leader: one change at
  a time, configuration entries that take effect when appended, promotion within
  `PROMOTION_LAG`, a commit on a majority of the voters alone, and the
  configuration rebuilt from the log at a restart. New checks
  `quorum_of_voters`, `configuration_from_log` and `learner_caught_up` run with
  every case (`check::membership`), and the reply check counts the voters of a
  server that reports a configuration. Scenarios M1 (add and promote, with a
  split that a core counting its learner would commit through), M5 (a lagging
  learner refused, then promoted) and M8 (a restart under an uncommitted
  configuration) run on the reference.

- A group's checkpoints in the Archive agent (phase 3, A9-3).
  `StartGroup::checkpoints` (`GroupCheckpoints`: `max_checkpoint`, and
  `reopen_hold`) gives a group a checkpoint store in its journal
  directory's `checkpoints` subdirectory (`checkpoint::store_dir`), made
  or recovered with its journal, recovery cutting it to what the
  journal's records name, a missing one marking their ranges lost, and
  closed with the group. Settings that cannot work are refused before
  anything is made (`AgentError::CheckpointConfig`). The group's sender
  carries a `CheckpointHandle` (`CaptureSender::take_checkpoints`), the
  Gateway's end of a one-slot handoff that moves the buffer both ways
  with no copy and no allocation; once the group stops, fails or ends,
  checkpoints are refused (`CheckpointError::Stopped`) with their buffer
  kept. The agent writes a checkpoint once its journal holds the event
  it names, in chunks of at most `AgentConfig::checkpoint_budget` bytes
  a cycle, then syncs it and records template 30, which the capture
  job's prefixes take (`CaptureJob::checkpoint`). The production
  coverage answers `Coverage::checkpoint` from the group's store. The
  capture job lifts its stop once a checkpoint opens a range, so the
  in-flight bound applies again, and a restart counts a gap's events as
  sent; an event the tracker has no room for then is taken again once,
  after a sync, and the group fails, typed, only if it is still full.
  The reopening window holds `reopen_hold` events (four times
  `in_flight` by default), and a range that could not reopen over them
  is counted (`PrefixTracker::failed_reopens`).
  `GroupWaiter::durable_for` answers per event across ranges.

- Replay with checkpoints (phase 3, A9-2). `ReplayCursor::open_at_checkpoint`
  reads a checkpoint's snapshot into the caller's buffer, checks its length and
  CRC-32C (`ReplayError::CheckpointCorrupt` otherwise, also for a lost one in a
  range it opened), and replays the events after its `group_seq` to the end of
  its range's complete prefix. One unknown, past that prefix, in a middle range
  (interim), or lost after a stop it never opened is refused
  (`UnknownCheckpoint`, `NotInPrefix`), as is a short buffer. The cursor gives
  each recorded checkpoint of the range right after its event
  (`Step::Checkpoint`); `compare_state` compares the replay's state there by
  length and digest and gives the capture's record at `CAPTURE_POSITION`.
  `ReplayGateway` does it in the event's own dispatch through the handler's new
  `checkpoint` hook (`ReplayGateway::with_state`); a difference, or no state, is
  a `DivergenceKind::StateCheckpoint` divergence, its index the event's
  observation count, and a snapshot above the buffer is
  `GatewayError::StateBuffer`. `ReplayCursor::step_from` skips the checkpoints
  below its start; the diff does not compare checkpoints yet. `Handler` gains
  `checkpoint` and `restore`, with default bodies; `CaptureJournal::create_from`
  starts a capture after a checkpoint. Steps allocate nothing.

- Checkpoints of a recording group, the store and the record (phase 3, A9-1).
  Each group has a `CheckpointStore` beside its journal, with the journal's sync
  policy. `CheckpointWriter::write` checks the record against the order rules,
  appends the snapshot's bytes and syncs them, then appends template 30
  (`CheckpointRecord`, block 40): a failed write leaves no record, and a
  recorded checkpoint is durable by construction. The Gateway's one-slot handoff
  (`CheckpointSlot`) refuses a checkpoint in flight, one above `max_checkpoint`,
  an empty one and any after a strict journal's end, each typed and counted. A
  new order rule (`OrderRule::Checkpoint`): recorded checkpoints name an ended
  event and rise in `group_seq` and id. The prefix tracker follows ranges: a
  checkpoint after a gap or an incomplete event opens a new one at its record
  once the store holds its bytes (`Coverage::checkpoint`, `CheckpointHeld`; a
  lost one opens nothing), reported by `PrefixTracker::range`. The first range's
  final values are frozen (`PrefixTracker::first_range`): replay from the start
  stops there, and `PrefixView::durable_for` answers a wait for an event before
  the current range from them. The replay cursor skips template 30. Recovery
  cuts bytes no record names and marks as lost a range a record names that the
  store lacks. Nothing allocates per checkpoint.

- Timed lanes over the network (P2.11 PR1, the software route).
  `EmbeddedDriver::add_timed_network_publication` adds a network publication
  whose lanes have a schedule ring: its sender holds each message until its
  requested time, then sends it, one message per datagram, and frees its
  schedule entry once it left, so the ring bounds only messages outstanding. A
  plain network publication whose lanes have a ring is timed with the default
  settings; before, its offers were back-pressured for good after the ring's
  capacity, as nothing freed it. Lateness, late sends and heads dropped by an
  unreliable reset are counted; a guard close ends a head still waiting for its
  time. Refused for now, typed (`DriverError::TimedNetworkUnsupported`):
  redundant paths, the `Tai` domain, cancel-on-deadline and a `max_horizon`
  that, with one `sender_heartbeat_interval`, reaches `image_liveness_timeout`
  (a lane holding only a head that far ahead sends nothing, so its images would
  retire). A lane's settings and counter cells are fixed from the add, also
  across a guard reopen's fresh incarnation. Counts are per message, not per
  fragment. On a reliable channel (PR1b) a message's schedule entry is held
  until the receivers acknowledge it, so `schedule_capacity` must cover the
  unacknowledged window (a smaller ring back-pressures offers until they
  consume); a reset reads the held entries again with
  `ScheduleReader::rewind_to_released`, and the messages it resends go at once,
  outside the late policy, counted as rewound. A NAK repair reads only the
  frames its request covers, as a timed lane sends one frame per datagram. The
  sender times heads on the host monotonic clock, as `Monotonic` offers are
  timed; no time namespace is checked, as on the local route. `TimedGate` keeps
  its API over a `TimedState`, which a sender holds across cycles and gates
  through a `TimedView`.
- The `replay` rejoin through the Archive end to end (phase 3, A6d):
  karyos-sim's `tests/archive_control.rs` wraps a lapped optional reader
  in a `ReplayRejoin` whose provider is the Archive's client, over the
  control streams, with the sim host as its `ReplayTargets`. The gap is
  replayed from the recording and merged back into the live stream at
  the resume, every message once, in order, byte-exact. A recording
  lapped before it was read reports its gap as the replay's local gap and
  merges what follows; a stream with no recording falls back with
  `NoRecording`.
- A removed routed publication sends each lane's EOS on every live path
  (redundant paths; rp-w5b follow-up). A lane is drained once its first
  sends reached its seal on every path that can send now; a path whose
  TX half is detached, that is resetting or that left the live set
  neither holds the drain nor gets the EOS, and one that returns during
  the linger gets the repeats. The EOS counts as sent once one path
  submitted it; a closed guard sends it on none. Routed removals no
  longer linger without EOS.
- karyos-client's `MessageInfo` gains `extent`, the bytes the message takes in
  the stream (its frames end at `position + extent`), and is
  `#[non_exhaustive]`, so later fields add without breaking; it was built only
  by the client. `ClientSubscription::poll_taking` is public: a handler that
  returns false declines the message, which stays pending for a required reader.
  karyos-sys's `FrameReader::ready_end` gives a complete message's end. For the
  recording group Gateway's sources (phase 3, A7d-2b).
- The recording group Gateway takes its inputs (phase 3, A7d-2b).
  `Gateway::add_subscription` adds a message source with its `SourceIdentity`
  and the `RecordingWord` of the recording that holds its stream;
  `Gateway::add_conflated` adds a conflated view, refused with
  `GatewayError::TooLarge` when its largest value could not be recorded. A
  dispatch fires the earliest due timer first, else takes one event from the
  next source or view in turn. A message whose length exceeds the inline
  threshold and whose position the recording holds is recorded by reference;
  otherwise inline up to `MAX_INLINE`; above it strict capture declines the
  message (`TooLarge`) and best effort records its payload as unavailable.
  `Event::Message` gains `extent`, `length` and `payload: MessagePayload`
  (`Bytes` or `Unavailable`); replay presents the same. A loss or an end a
  source reports stays held while strict capture refuses it, and strict capture
  polls a view only when it can admit the event, since reading a value consumes
  it. `set_inline_threshold` and `set_observation_budget` tune placement and
  observation. The Archive's `ArchiveHandle::recording_word(stream, session,
  lane)` gives the shared word naming a required recording of that lane and its
  start; the word clears when the recording stops, ends or fails. A Gateway
  takes one source per stream and session (`GatewayError::DuplicateSource`).
  Strict capture reads a source or a view only when it can admit the event; a
  message it read and cannot record ends the journal at an incomplete skipped
  range. `Event::Conflated` carries the value's key. karyos-client's
  `ConflatedSubscription::config` gives a view's table configuration.
- The recording group Gateway (phase 3, A7d-2a).
  `karyos_archive::group::gateway` holds the `GroupGateway` trait that capture
  and replay share: `Event`, `Effects` (clock, offer, a scoped claim,
  `poll_outcomes`, timers, external reads), `Handler`, `Dispatched` and
  `GatewayError`. `gateway::live::Gateway` captures: it reads the clock once per
  event, numbers it, delivers it, and records the event and each call into an
  event buffer allocated at configuration, sent as one ring message; the
  publications are reached through a `Port`. Strict capture never delivers or
  performs what it cannot record, refusing it typed (`GatewayError::Refused`,
  `Outcome::Gated`); best effort delivers it unrecorded and coalesces the events
  refused in a row into one gap marker with the first refusal's reason.
  `deliver_external` dispatches an input from outside Karyos. Template 11 gains
  the output intent's `length` and `crc32c` (block 59), and template 15, the
  delivery poll, precedes its delivery outcomes, under a new order rule.
- The Archive's agent captures recording groups (phase 3, A7d-1c).
  `ArchiveHandle::start_group` makes a group's journal (or recovers it) in the
  host's group directory and returns its `CaptureSender`; the agent serves the
  group's job after the recorders, and `stop_group` refuses the group's sender,
  drains its ring into the journal, bounded by the ring, and closes it. Settings
  that cannot work are refused before the journal is made, and a start past
  `max_groups` is counted in `refused()`. A group's references are covered by
  the agent's recordings: an active `required` recorder's written and durable
  positions, and a stopped `required` recording's end, also after a restart. A
  recording that fails, with no stop in the catalog, has its references settled
  by its frames durable at the failure, also those drained after it; it holds
  its slot under the recording cap until every running group has read past the
  failure. The catalog records each recording's mode in its `Started` record (an
  optional last byte under version 3, covered by the CRC; an entry without it
  reads back as `async`), and `Recording::required` reports it. `AgentConfig`
  gains `max_groups` and `group_budget`.
- A recording group's capture path (phase 3, A7d-1b).
  `karyos_archive::group::capture` makes a group's `CaptureSender`, for the
  event loop, and `CaptureJob`, for the Archive's thread, over one command ring:
  each message is an event's records. `admit` takes an event only when the ring
  has room for the largest one, with a wrap's padding, both ends counting in the
  ring's own framed positions, and fewer events are in flight than the prefix
  tracker holds (until the prefixes stop); a gap needs only room. Its refusals
  are typed. The job appends each message to the journal, feeds the tracker and
  advances the prefixes; `recording_ended` counts the references a stopped
  recording covers as covered, and marks the others unavailable (best effort) or
  ends a strict group; a reference that reaches the job after its recording
  ended is settled when read (`Coverage::ended`). A strict incomplete event ends
  the group. A `GroupWaiter` waits for durability off the event loop; the job
  only notifies it. A journal failure fails the group. `capture` refuses a
  journal that never syncs (`SyncPolicy::None`), a recovery with more events
  waiting than the tracker holds, and settings whose arithmetic would overflow;
  under `PerSegment` the job syncs at the in-flight bound.
- A recording group's records for the Gateway (phase 3, A7d-1a), in place under
  schema 3 version 1. A message's payload can be unavailable (value 3): above
  `MAX_INLINE`, from a source this Archive does not record as `required`, with
  its length, position and extent and no value. A `LossEvent` (template 7) is an
  event for what a source reported instead of a message: an overrun with its
  rejoin outcome (replaying and replayed among them, and a `replay` fallback's
  reason), a skipped range with its reason, or an aborted block, with `from`,
  `lost_to` and `resume`. A `ReferenceUnavailable` (template 22) marks, in a
  best-effort journal, an ended event whose referenced recording stopped before
  covering it: the order rules take it between events, naming an event that
  ended at or after the first, and refuse it, and payload 3, in a strict
  journal. The prefix tracker settles a waiting event that references that
  recording, also after the prefixes stopped, and counts it complete; a mark for
  an event already durable, or at or past the stop, is a no-op, and one inside
  the stopping gap is refused.
- A recording group's three prefixes (phase 3, A7c; SPEC §8.3).
  `karyos_archive::group::prefix::PrefixTracker` tracks `delivered_seq`,
  `complete_recording_seq` and `durable_group_seq`: an event is complete
  once its records through its end are written, its end is complete and
  the payload it names by reference is written in its recording, and
  durable once all of those are durable. An incomplete event or a gap
  stops both prefixes. Events not yet durable wait in a queue sized when
  the tracker is made; one with no room is refused. A `PrefixView`
  publishes the three values, each a wait-free load, and
  `prefix::recover` recomputes them from a recovered journal. The
  journal's `walk` now gives each record's end too.
- A recording group's journal on disk (phase 3, A7b).
  `karyos_archive::group::journal::GroupJournal` keeps a group's records
  back to back in a segment store named by the group (written and durable
  positions, sync policies, CRC-32C, torn-write recovery of A2). Every
  record appended is decoded and checked against the order rules first,
  so a refusal writes nothing. A record never spans two store writes: a
  segment's end is padded (a fill, or zero bytes under 32), so recovery
  always cuts between records; it then reads every record kept and
  checks it again.
- A recording group's journal records, schema 3 version 1 (phase 3,
  A7a; SPEC §8.3, ADR-0024). `karyos_archive::group::record` holds the
  journal header (group, first `group_seq`, inline threshold, capture
  contract, clock provenance, strict or best-effort capture, the
  caller's manifest), five event records (a message with its reserved
  value, end of stream and trace extension, inline or by reference to a
  required recording; conflated value; timer; lifecycle; external), four
  observations (offer, claim and commit outcomes with the client error
  code; timer create and cancel; external; delivery outcomes), the event
  end and the gap marker, hand written on the
  `karyos-codec` runtime as A1. `karyos_archive::group::order` checks a
  journal's order rules with fixed state. Nothing allocates.
- A segment store is truncated at the end of a write
  (`SegmentStore::truncate`; phase 3, for a recording group's recovery
  to its complete prefix, SPEC §8.3). Everything after the cut is
  removed on disk and what is kept is durable on return; a crash inside
  recovers either as before or at the cut. A position outside the
  recording or inside a write is refused, typed, with nothing changed.
- `karyos_sys::submission_frontier::SubmissionFrontier`: a guarded
  network lane's submission frontier, which its sender gate publishes
  for the driver's outcome walker. Per lane, `resolved` (Release),
  `unknown_hi`, `sent_hi` and `staged_hi` (Relaxed, stored before it),
  all monotone and written by the gate alone, and a final word that the gate
  (`finish`) or, once the gate stopped for good, the conductor
  (`supersede`) sets once, by compare-exchange. A Loom model
  (`loom_submission_frontier`) checks the orders and the race of the two
  final writers, with three negative controls.
- Per-path datagram and byte counts (RP-10; rp-w9). Each route of a
  routed publication counts the datagrams and bytes it submitted,
  catch-up copies included (`RouteCounters::datagrams`, `bytes`), and
  `Outbound::path_counters` reports them (`PathCounters::datagrams`,
  `bytes`) for capacity planning. The DRR still charges a frame once,
  however many paths take it.
- Receive path queues (rp-w8). A multi-path image's DATA datagrams and
  heartbeats wait in their path's queue between the endpoint's receive poll and
  the image, and the receiver serves the queues round robin after every poll, so
  a fast path cannot starve a slow one. A full queue drops only that path's
  datagram, counted in `ReceiverCounters::path_queue_drops`; with no free queue
  a datagram is delivered at once (`path_queue_bypassed`), and a path never
  switches between the two while its queue holds datagrams, so its order holds.
  Each datagram keeps its poll's time as its arrival for the statistics, skew
  detection and liveness. `AgentConfig::path_queue_datagrams` (256) sizes each
  queue; the queues take `sessions.max_paths × path_queue_datagrams × 8 KiB`
  (8 MiB by default, at most 64 MiB, validated), allocated when the first later
  path is bound and kept: a single-path receiver allocates none. The queues are
  per local receive endpoint and live in one slab; a control on an endpoint
  first delivers that path's queued datagrams, so a reply never overtakes them;
  queued datagrams are counted (`path_queued`) (rp-w8b).
- The live set of a routed publication's paths (RP-8; rp-w5a). Each path keeps a
  `path_lag_limit` window (100 ms) of bytes selected and skipped: one that
  skipped anything is `Degraded`, and one whose skipped share passes
  `path_skip_ratio` (50%, once `path_skip_min_bytes`, 64 KiB, were selected), or
  that the lane waited on alone for longer than `path_lag_limit`, leaves the
  live set while another path remains (`AgentConfig::path_policy`, validated at
  start). A path out of it takes no copy and no flush and holds no head back
  (`RoutedLaneSender::set_live`); its never-exposed copies come back
  (`RoutedLaneSender::cancel_route`) through the guard gate; those it held alone
  are counted (`PathCounters::copies_abandoned`) and reach receivers by NAK or
  close as gaps. `Outbound::path_state` and `Outbound::path_counters` report it.
  A faulted route leaves too, while another path is live.
- A left path returns (RP-9; rp-w5b) after its backoff
  (`PathPolicy::backoff_initial`, 10 ms, doubling to `backoff_max`, 1 s
  and at most `MAX_PATH_BACKOFF`, 60 s, and starting over after
  `backoff_reset`, 10 s, live): on its open queue,
  or by `retry_queue` after a fault, from the current selection point,
  counted (`PathCounters::entries`). It bounds `Outbound::sent_low`, the
  least frontier over the live paths, from its first submit; a frame a
  path skipped counts as passed for its frontier.
- Repair across redundant paths (RP-11; rp-w6). A routed publication opens a
  repair queue on every route. Each repair datagram is read once and submitted
  on every live path, debited once at its first submission
  (`RouteRepairCounts`, `Outbound::repair_route_counts`). A path with no room
  skips it, counted, so a lagging path never holds a job open. The NAK's
  arrival path goes with it: a copy of a NAK on another path within
  `PathPolicy::skew_window` (1 ms, at most 1 s) is absorbed and counted
  (`nak_copies_absorbed`), from a table of `PathPolicy::copy_entries` (256, at
  most 4096) that stops absorbing when full. The admission order is now the
  binding check, the absorption and then the NAK budget, so an unbound NAK
  counts `nak_unbound` even when the cycle's budget is spent. A step 8 ERR
  goes once, on the path its requester asked on. Group repair only: the
  requester domain stays deferred.
- A close no longer waits on a detached path (rp-w5b). On a guarded lane's
  abort, the copies of a route whose TX half is detached are forgotten through
  the guard gate (`RoutedLaneSender::forget`), so the close can become effective
  if the path never comes back, and counted (`RouteCounters::forgotten`). The
  route then returns only through an endpoint reset.
- Receiver trace journals keep their sealed gaps (P2.12 step 3, PR 3b): the
  first `FACT_GAP_INTERVALS` (16) gaps of each traced lane, in order, with an
  overflow flag, carried in `JournalFacts::gaps`.
  `EmbeddedDriver::network_journal_gaps` returns a closed receiver journal's
  gaps for an in-process report. `SkipPolicy::duty_observed` and
  `range_unavailable_observed` tell a callback of each committed seal; `duty`,
  `duty_gated`, `range_unavailable` and `range_unavailable_gated` delegate to
  them.
- Network publications over redundant paths (rp-w4b2c): a multicast IPv4 channel
  with `paths` sends on one endpoint per path, each bound to its path's
  interface address, as one routed publication; each path holds its send
  endpoint and the receiver's published alias, released and retired with the
  publication. Refused with `DriverError::UnsupportedChannel`, and counted,
  while the sockets cannot be isolated per path (`SocketOps::isolates_paths`);
  unicast `paths` stay refused.
- The sender over a routed publication's paths (rp-w4b2b): a SETUP side on each
  path's endpoint, established on any path; SMs, NAKs and bindings found on any
  path (`Outbound::serves`, `Outbound::destination_on`); and a PATH_HB on each
  path idle for `AgentConfig::path_heartbeat_interval` (default 100 ms, an
  interim for the channel heartbeat interval RP-3 names), counted by
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
- Receiver network trace points (P2.12 step 3, NT-2 to NT-4). The receiver agent
  writes one journal per lane of an installed image: `OpenNetworkJournal` starts
  it at the lane's next commit position (the image join fact); a traced DATA
  frame records one `ReceiverCommit` when it commits, naming its path (a repair
  that fills a hole records too), and copies of an already committed frame
  record nothing; `CloseNetworkJournal` answers the start, the lane's resolved
  prefix as the commit boundary and its first sealed gap. An image that retires
  closes its lanes' journals at once and posts their facts as
  `NetworkJournalClosed`, retried while the event ring is full; a later close
  answers the same facts once. New receiver counters: `net_trace_ext_invalid`
  and `net_journals_retired_dropped`.
- Conflated views of network images (C4).
  `EmbeddedDriver::add_network_subscription_conflated` names the lane and the
  view's `ConflationConfig`. When the image of such a key is exposed, the
  conductor builds a heap table over the image's `FreshnessLink`, feeds it from
  a required subscription of the lane and attaches it to the mailbox. Each duty
  the feeder first records a gap met in the log (held, and nothing past it
  polled, while the barrier is full), then serves the seal request,
  acknowledging only after the loss is recorded (withheld while full), writes
  values with their positions (`write_at`) and reconciles in bounded passes. A
  published terminal cell closes the feeder.
  `EmbeddedDriver::network_view_counters` reports `NetworkViewCounters`: views
  built and not built, acknowledgements given and withheld, gaps recorded from
  the log, views closed by their terminal cell.
- The receiver gates a conflated network image lane's seals (C3).
  `AddSubscription` carries the conflated lane (driver-internal entry
  `EmbeddedDriver::add_network_subscription_conflated`; subscriptions sharing a
  receiver entry agree on it, `DriverError::ConflationMismatch`). At install the
  receiver allocates the image's `FreshnessLink`, hands it to the conductor with
  `ImageInstalled` (`ImageTable::freshness`) and seals that lane through a gate
  over its barrier mailbox: at once while no feeder is attached, after the
  feeder's acknowledgement once one is, and past
  `AgentConfig::barrier_ack_timeout` (default 100 ms, at least 10 ms) after
  publishing the view's terminal cell, waiting while a feeder's claimed cell is
  unpublished. New receiver counters: `seals_gated`, `barrier_posts`,
  `barrier_acks`, `seals_unattached`, `barrier_timeouts`, `barrier_claim_waits`,
  `barrier_post_failures` and `conflated_lane_out_of_range`.
- Conflation freshness for network images' views (C2): `conflation_fresh` builds
  a heap table with a loss barrier over the terminal cell of a `FreshnessLink`
  (a seal mailbox and a terminal cell in one allocation, shared with the image's
  receive owner). Its writer records a loss (`record_loss`, refused below the
  frontier with the terminal cell published, or while the ring is full), writes
  values with their freshness (`write_at`,
  `FreshSlotWords::write_with_freshness`), reconciles the slots in bounded
  passes and retires the records (`reconcile`), and counts the work
  (`FreshCounters`). It refuses a value without its position
  (`ConflationError::PositionRequired`) or below its frontier
  (`ConflationError::BehindFrontier`), and a terminal close also closes the
  table. The reader classifies each copied value against the barrier and the
  terminal cell: `ConflationReader::poll_changed`'s handler gets the `Freshness`
  as a fourth argument, a new loss serves every written key again, and after the
  terminal cell nothing is delivered (`PollReport::terminal`). Terminal reasons
  are `TERMINAL_BARRIER_TIMEOUT`, `TERMINAL_FRESHNESS_EXHAUSTED` and
  `TERMINAL_BELOW_FRONTIER`. Tables without a barrier deliver every value Fresh;
  the client's `ConflatedSubscription` keeps its signatures.
- `karyos_io::lanes::routes::RoutedLaneSender`: one DRR over a lane's queues on
  up to `MAX_ROUTES` routes (RP-10). A lane's head is selected once, submitted
  on every route that holds it at its front, and debited once; `catch_up` sends
  the copies of routes that fell behind, debiting nothing, and reports a failure
  in `CatchUp`. With several routes a failure stops only its route, kept for the
  control path (`take_failures`), and a route without a TX half this call is out
  for the call. `RouteCounters` count skipped, late and uncancelled copies per
  route. `StageError::OutOfOrder` refuses a copy not above its route's last one.
- A publication over redundant paths (RP-10): `Outbound::new_routed`
  (crate-internal: test-only until the publication wiring) takes one endpoint
  and destination per path, and `Outbound::serve_routes` sends each committed
  datagram once on every path, debited once
  (`karyos_io::lanes::routes::RoutedLaneSender`). Repair stays on the founding
  path, on its queues. A route's failure resets only its endpoint
  (`Outbound::post_reset_requests`) and a faulted queue is retried on its route;
  a reliable lane reads again after a reset only when no route still holds its
  copies. A guard covers every path (`GuardGate::new_routed`,
  `GuardGate::stage_copy`, `GuardGate::reopen_route`): each copy's exposure
  loads the guard, a position is rate charged once, the applied positions are
  the highest submitted on any path, and the work in flight counts every path.
- A seal gate on the skip policy: `SkipPolicy::duty_gated` and
  `SkipPolicy::range_unavailable_gated` ask a `SealGate` before each seal. While
  it answers `GateAnswer::Pending`, the hole stays due, `SkipReport::gated`
  counts it, and the hole is posted to the receive owner
  (`ReceiveOwner::post_seal`, `ReceiveOwner::posted`): a frame overlapping a
  posted interval is not committed and reads `Received::LateAfterSkip`, so the
  interval is sealed whole. `duty` and `range_unavailable` use `Ungated`, which
  always permits, and seal as before.
- `karyos_sys::freshness::BarrierMailbox` (`MAILBOX_WORDS`, `SealRequest`,
  `FreshnessError::UnknownRequest`): one lane image's seal mailbox between its
  receive owner and its conflated view's feeder, words
  `[request, start, end, ack, attached]`. The owner posts the interval it
  intends to seal and seals after the acknowledgement; the feeder acknowledges
  only after its barrier published the loss. The Loom model
  `tests/loom_barrier_mailbox.rs` checks it with the barrier, a fresh slot and
  the terminal cell: four scenarios (acknowledgement, timeout, ring-full race,
  attach race) and seven negative controls.
- Receiver roles and tags reach the network agents, driver-internal (MC-1, MC-2;
  no public API yet). A network publication can carry `PublicationRoles` (its
  strategy, required receiver ids and tagged ones), which build its membership,
  now created at the add's time so a required receiver's join is timed from it.
  A network subscription can carry a `ReceiverIdentity` (a configured
  `receiver_id` and its `group_tag`), which its images name in every RB block
  (SMs, NAKs, RTTM requests and reply matching) instead of the id derived from
  their slot. Subscriptions sharing a receiver entry must agree on its identity
  (`DriverError::ReceiverIdentityMismatch`, `ErrorCode` 15). An SM whose
  declared tag is not the one configured for its receiver is dropped whole
  before the sender's binding (`SenderCounters::sm_tag_mismatch`), so it never
  establishes a session or holds retention (MC-2).
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
- Redundant paths at the receive owner (P2.9): `karyos_driver::paths` with
  `PathConfig` (`max_paths`, `path_queue_datagrams`, `skew_sample_frames`,
  `path_skew_window` validated in 0 to 1 s), `skew::SkewDeadline` (fixed at
  detection, no window below two live paths, the larger of reorder and skew on
  unreliable channels), `queues::PathQueues` (bounded per path, drops counted
  per path, served round robin) and `stats::PathStats` (wins, duplicates, stale
  replays, conflicts, per-path `Late`, missing bytes per whole term of a binding
  from fresh deliveries only, arrival differences from a ring of first arrivals
  per lane, and freshness per path for path liveness, the mark seeded at the
  path's join and kept across a loss).
- Redundant path bindings at the receiver (P2.9):
  `sessions::paths::PathBindings` binds an image's first path at installation
  and later paths of the same identity, alias, term parameters and lane count
  through their own challenge (RP-1: their joins are recorded, never applied); a
  path's liveness takes only fresh evidence and PATH_HB, and a lost path leaves
  no tombstone. The receive sessions answer a later path with
  `AnswerOutcome::PathBound`, with no image created and no conductor chain
  reserved, refuse a full image (`Ignored::PathsFull`), and keep refusing an
  identity challenged or answered under another key. `SessionConfig` gains
  `max_paths` and `path_liveness_timeout`. The path rows decide admission:
  `lookup` and the bound-key checks go through them, so a first path lost at its
  timeout stops admitting and returns only through a fresh challenge, as a later
  path. `ReceiveSessions::timers` removes lost paths within `timer_actions`. Not
  wired yet: refreshing a path on fresh DATA and PATH_HB intake, which phase 5c
  calls through `paths_mut()`.
- RTT observations (P2.7 B, RC-1): `karyos_driver::rtt::RttProbes` probes each
  path of an image with at most one outstanding RTTM REQUEST (random nonzero
  64-bit ids from `ProbeIds`, so an off-path spoofer cannot forge a reply; in
  the driver a pool, `OsProbeIds`, drawn from the operating system on the
  control path and restocked by `refill_ids` once at or below half full, so the
  duty path makes no system call and a refill each control cycle is free in
  steady state; an empty pool or failed draw is counted), samples only submitted
  probes from the time read before the submitting call to the validated reply,
  never subtracts `service_delay_ns`, raises a sample below `rtt_floor` to it,
  refuses a zero sample, keeps the largest of the last `rtt_sample_window`
  samples as the path's estimate (`rtt_initial` before any or after a rebinding)
  and gives NAK timing the largest estimate over the live paths (`snapshot`). A
  path whose binding generation is exhausted stops probing and is counted, never
  wrapped. `RttReplies` limits a sender's replies to `rttm_reply_rate` per
  second per source endpoint, in a bounded table of `rttm_reply_sources`, so one
  source cannot starve the others.
- Multicast receiver membership and flow control (P2.7 A, MC-1 to MC-9):
  `karyos_driver::membership::Membership`, one publication incarnation's
  receiver table, owned by its sender agent. It takes SMs the session binding
  validated (`SmKey`) and keys members by `receiver_id` and `receiver_boot_id`,
  with a checked generation per slot (`MemberRef`, `current`) and retired slots
  at exhaustion. A member records up to `max_paths` bindings, so one receiver
  over several paths stays one member; `binding_gone` removes a binding, and the
  last one removes the member (a required one is lost, M5). Roles and tags are
  configured (`Roles`): a mismatched `group_tag` rejects the SM, and a required
  receiver has one membership per incarnation. The join fixes each lane's window
  in `min_window..=max_window`; a changed window, a stale or impossible
  consumption (above `sent_high`) or an overflowing edge rejects the whole SM.
  An SM is fresh when it advances a lane or reports `sent_high` on every lane; a
  stationary member lives until `pause_timeout` (default 60 s), counted as
  `stationary` and `paused`. `limit` gives a lane's edge (the strategy's
  extremum, `min`, `max` or `tagged`, then the minimum with every live required
  edge), `NoReceiverWindow` or `Held`. `admission` opens once the required set
  has joined and stops for good at a required loss, whose last consumption stays
  in `retention`. An expired optional member leaves a tombstone: it rejoins only
  with an SM fresh against its last consumption or after a new `expect`, so
  stationary SMs cannot defeat `pause_timeout`. Only an establishment (`expect`)
  or a configured required receiver may take another receiver's tombstone slot,
  an `expect` refused for its limits keeps the tombstone, and an SM's credit
  faults are counted before the tombstone's. `timers` expires members within a
  bound with a fair cursor, and membership events are queued in a bounded queue.
  Not wired yet: the sender agent's SM handoff and gate.
- Receiver SM schedule (P2.7, M3 and MC-6):
  `karyos_driver::sm_schedule::SmSchedule`, one per image. It makes the first SM
  due at once, then one every `sm_interval` (by `age_ns`), and one as soon as a
  lane's consumption advances by a quarter of its window. The SM reports, per
  lane, the larger of the given and the last reported consumption, so it is
  never stale at the sender; a lower value is counted as a regression. An SM is
  recorded only once sent, so an unsent one stays due. Not wired yet: the
  receiver agent's SM path.
- NAK admission at the sender (phase 6 R4):
  `karyos_driver::repair::admission::Admission` runs steps 1 to 5 of the
  eight-step order, the first failure deciding. Context and the requester window
  drop with no reply, each counted: an unreliable publication, an unknown
  requester or lane, a range below the join point (counted apart before any
  accepted SM), below the consumption (stale) or beyond `consumption + window`.
  A range leaving its term, or beyond the NAK bound, answers `RANGE_INVALID`;
  one below the floor answers `RANGE_UNAVAILABLE` with the floor, before the
  frontier check. At most one ERR goes per receiver, lane and range within
  `nak_reply_linger`, from a bounded table. A passing NAK is a `Request` for the
  job table (R5). `Membership::requester` gives what a NAK is checked against: a
  live member's join point, consumption and window, or an expected entry's
  answered join point before its first SM (`expect` now takes the answer's
  joins).
- Repair jobs and coalescing (phase 6 R5, RC-11):
  `karyos_driver::repair::jobs::Jobs`, steps 6 and 7 of NAK admission. The key
  is the lane, the exact range and the response domain (`Group`, or `Requester`
  with the receiver and its membership generation); an exact duplicate joins the
  pending job and adds its requester, and nothing wider merges. The linger
  (`repair_linger`, 1 ms) starts at the last frame's submission and drops
  duplicates without extending; a known failure or an uncertain submission
  starts none. `repair_jobs` (64) and `repair_linger_entries` (256) are bounded:
  a full table drops and counts. Jobs keep their unsent cursor and a checked
  slot generation; requester lists are allocated at construction.
- Repair scheduling (phase 6 R7, RC-12 and RC-13):
  `karyos_driver::repair::scheduler::Scheduler` serves the pending jobs with its
  own protocol `Drr` over the lanes, with the data path's quanta, within the
  repair budget (64 KiB, 4096 word 0 loads), so a budget too small for a head
  keeps the lane's deficit. Each lane serves its oldest job from its cursor, one
  whole frame at a time, read through `RepairRead` (a DATA frame charged its
  aligned length, PAD and ABORTED 32 bytes) and submitted through
  `RepairSubmit`. At each head, step 8 and the end proof: `BadRequest` or an
  extent crossing the end answers `RANGE_INVALID`, `Unavailable` or `Revoked`
  answers `RANGE_UNAVAILABLE` with the floor read after, both to every
  requester; `CorruptTerm`, `Retry` and `TooSmall` drop the job with no ERR. A
  submitted last frame ends the job and starts its linger; an uncertain one ends
  it unresolved; no room stops the call as backpressure. A probe reads at most
  one head, so reads and ERRs stay within the loads budget; a known failed
  submission holds its lane for the rest of the call; a head the DRR would
  refuse is dropped and counted. The round robin across incarnations is the
  wiring's. Not wired yet, and the NAK read origin in karyos-sys comes
  separately.
- Repair simulator scenarios (phase 6): karyos-sim's `tests/repair.rs` runs NAK
  admission, the job table and the repair scheduler together on virtual time
  against a scripted two-lane log and backend, 40 seeds each. `repair-mixed` has
  receivers NAKing identical, overlapping and malformed ranges with duplicates
  and reorder, a floor that moves, random budgets and every submission outcome;
  it checks that every job ends exactly once and is never served after, that no
  duplicate within `repair_linger` creates a job, that no ERR repeats within
  `nak_reply_linger` (step 8 ERRs included), and that `RANGE_UNAVAILABLE` names
  the floor of that moment. `repair-fair` checks that two backlogged lanes stay
  within `Q + 2 F` of each other. Each oracle fails under a mutant of the
  components.
- NAK reads in the sender read capability (phase 6): `SenderRead::read_nak(from,
  NakRead { bound, loads }, out)` copies whole frames from an untrusted NAK
  position below the NAK bound, never moving the cursor, the open block, the
  registered position or the boundary ring, and never feeding C-9. The position
  is proved a frame boundary by a word 0 walk from a checkpoint
  (`nak_checkpoint_stride`, default 64 KiB, `SenderRead::with_nak_stride`):
  every frame the cursor path copies records, per stride it passes, the first
  frame start at or after the stride with its block's end, in arrays tagged with
  their term count, cleared on a new count and read only for it. The walk goes
  frame by frame, charging each load before it is made, and takes the end of a
  block it enters from the cursor's open block, the next stride's entry or its
  END: from the entry of its own stride a scan spends at most `stride / 32 + 1`
  loads and returns the loads spent; it never reads a payload word. A NAK at an
  uncommitted block is `BadRequest`. New `ReadError::BadRequest` and
  `ReadError::Budget`, and NAK counters.
- `SenderRead::floor`: the retention floor its reads enforce (Acquire),
  for NAK admission to check requests against before the read.
- Membership simulator scenarios (P2.7 C preparation): karyos-sim's
  `tests/membership.rs` drives `Membership` on virtual time, 40 seeds each.
  `membership-required-loss` stops admission exactly `receiver_timeout` after a
  dead required receiver's last SM, holds every lane and keeps its consumption
  in retention. `membership-optional-pause` checks that a paused optional
  receiver past `pause_timeout` does not rejoin on stationary SMs, that the
  sender moves past its edge, and that it rejoins once it advances.
  `membership-two-paths` checks that SM copies over a second path, and that
  path's bindings coming and going, match a one-path shadow table at every step.
  On every step the sent position stays within each required member's edge.

- Cross-process data streams on Linux (d1 to d4). `EmbeddedDriver::with_ipc`
  builds a driver whose every stream, successors included, lives in a shared
  region; the driver's and the client's handles are generic over the term
  backing, `HeapTerms` by default, so embedded callers compile unchanged. A
  remote client's `Add*` reserves its participant under an export id and records
  the grant in the client's export ledger, bounded by
  `IpcConfig::max_exports_per_client`. `Fetch` is answered with a `Manifest` and
  a `Region` carrying the region's descriptor, within `max_fetches_per_client`,
  `max_regions_per_fetch`, `max_fetch_bytes` and `fetch_deadline`.
  `RemoteClient::take_publication`, `take_concurrent_publication` and
  `take_subscription` check the manifest against the request and adopt the
  grant; dropping a handle unmaps it and sends `Detach`, and the last reference
  sends `Leave`. A client's close, exit proof or retirement ends its grants.
  karyos-sys ends a dead participant's registration: an exclusive writer's
  pending range is closed as PAD or ABORTED, and a concurrent publisher's slot
  is freed once the commit deadline passed its blocks. Tests run publishers and
  subscribers in separate processes, and kill or stop writers mid-offer,
  mid-record and across a term end.
- Mapping cutovers across processes (d5). A cutover reserves a successor grant
  for every remote participant and tells its client with the CnC event
  `SuccessorReady`; a successor not adopted by the cutover deadline is fenced
  and reported `Fenced`, the fence and the adoption excluding each other by one
  compare-exchange. `RemoteClient::poll` fetches and prepares the successor, and
  the handle activates it at the seal without allocating. The seal word gains a
  successor bit (bit 61; `LogBuffer::sealed_with_successor`), so a remote handle
  waits at a cutover's seal and ends at once at a final one. A client that
  lapped its broadcast buffer asks again with `QueryCutover`, answered by
  `CutoverState`. `reconfigure_stream` no longer refuses a stream with remote
  participants.
- Losing a required participant (p4a to p4c). The client and the driver each
  advance a heartbeat word; the driver times out a client silent for
  `client_liveness_timeout` and stops serving it, and a client presumes the
  driver lost after its own timeout. `StreamConfig::on_required_loss` selects
  `hold`, `continue` or `abort` for a lost client's subscribers: the participant
  is revoked and its reader polls `PollOutcome::Revoked`
  (`PollSummary::revoked`), and under `abort` the stream is sealed. The driver
  broadcasts `ParticipantLost`, `RequiredBoundWithdrawn` and `PublicationClosed`
  events, which clients queue for `take_events`. Tested with stopped and killed
  subscriber processes, Loom models and simulator scenarios under each policy.
- The observer role (P2a): `SubscriberRole::Observer` (wire 2) and the admission
  capability `ObserverSubscriber` (code 5). An observer never bounds the
  publisher's limit, holds a spare-slot credit like an optional reader, keeps
  the publication connected, and is lapped and rejoins at the head.
- Rejoin policies of an overrun reader (P3b): `ClientSubscription::with_rejoin`
  takes `RejoinAtHead` (the default); `Snapshot`, whose `SnapshotSource`
  rebuilds the state once before the first message after the overrun; `Close`,
  which ends the subscription and releases everything it holds; or
  `Replay { secondary }`, which applies its secondary policy with
  `ReplayFallback { reason: NoArchive }` until an Archive provides replays.
  `PollSummary` gains `rejoin` and `closed_by_overrun`. A generation link's
  close is terminal.
- Keyed conflation end to end (P5, p5c). `ConflatedSubscription` reads the
  latest value of each key (`poll_changed`), and publications key a message with
  `offer_with` and `try_claim_with`. The driver feeds a stream's keyed table
  from a required subscriber (`EmbeddedDriver::subscribe_conflated`) and ends
  the stream with `ConflationFeederLost` if the feeder cannot go on. An IPC
  driver places the table in a driver-only region, and a remote client takes a
  read-only view of it: `AddConflatedSubscription`, `ConflatedReady` and
  `RemoteClient::take_conflated`, checked against `ConflatedLimits` and rolled
  back on any failure. The feeder counts `conflation updates written`,
  `conflation keys rejected` and `conflation values too large`, and a view
  `conflation skips` and `conflation budgets exhausted`.
- A typed seal reason (#96). `SealReason` (`Unspecified`,
  `RequiredParticipantLost`, `ConflationVersionsExhausted`, `StreamRemoved`,
  `ConflationFeederLost`, `GuardClosed` and `DeadlineMissed`) is stored before
  the seal, so readers get it with `PollOutcome::Closed` and
  `PollSummary::close_reason`, and publishers through `seal_reason`;
  `CloseReason` shares its codes. An exclusive publication that meets a guard or
  deadline seal reports `Gated`.
- Observability for tools (P7). The counters layout version 2 adds three key
  words and the position and timestamp types, read against the host monotonic
  clock. The driver's diagnostic regions are driver-only, sealed so that clients
  and tools can only map them read-only. The driver samples each stream's limit,
  head and floor and each subscriber's position in a consistent pass, and gauges
  quarantined slots, spare reservations and loans. New error log and loss report
  rings; a client counters region with `AllocateCounter` and `ReleaseCounter`;
  `ReportLoss`, a subscription's report of an overrun with its publication's
  identity; and tool attach (`ToolHello`, `ToolAdmitted`, up to `max_tools`),
  which hands a tool the diagnostic regions read-only.
- `karyosd` (o5), a daemon that runs one driver in IPC mode. On SIGTERM or
  SIGINT it stops admitting (a `Hello` is refused with the new code
  `SHUTTING_DOWN`), removes every stream and lingers until clients leave
  (exit 0) or the linger ends (exit 3); a startup error exits 2, and a driver
  that enters its terminal state exits 4. New dependencies, for karyos-tools
  only: signal-hook, tracing and tracing-subscriber.
- `karyos-stat` and `karyos-errors` (o6), tools that attach read-only.
  `karyos-stat` prints the driver counters, each stream lane's limit, head,
  floor and headroom with each subscriber's position and lag, and the client
  counters, every `--interval` or `--once`, marking a sample that is not
  consistent. `karyos-errors` prints the error log and loss report records, and
  `--follow` keeps printing until the driver exits. Both need Linux and exit 2
  elsewhere.
- Tracing connected to the data path (P6). karyos-protocol's `TraceHook`,
  implemented by karyos-trace's `TraceAgent`; client tracing with
  `offer_with_trace`, `try_claim_with_trace` and `MessageInfo::trace`; a random
  `driver_id` per driver, also its admission instance id; and `TraceReport`,
  with per-publication latency histograms. Trace journals live in regions of
  their own (`TraceJournal`), which the driver drains into a driver-only trace
  mirror, and the new `karyos-trace` binary reads the mirror (`--dir`,
  `--follow`, `--interval`).
- The network receive path (P1, P2.6). `ValidatedDatagram::parse` checks a whole
  datagram against an image's parameters before anything is written. An image
  (`PublicationMode::Image`) is a lane written only by its `ReceiveOwner`, which
  commits each frame once and compares later copies, and its readers report what
  the owner cannot check as `PollOutcome::Skipped` with a `SkipReason`. A
  `SkipPolicy` seals a hole as a local gap record (`SkipReason::LocalGap`):
  after the reorder timeout on an unreliable channel, or after
  `RANGE_UNAVAILABLE` under `on_unrecoverable = skip` on a reliable one. A late
  copy into a sealed gap is `LateAfterSkip`, and gaps and reader losses are
  counted.
- Network control messages (P2.2, P2.8 B3a): karyos-protocol's codecs and
  dispatcher for the trusted network control messages, and a protection seam
  with the `Trusted` profile and a `Synthetic` test profile.
- The UDP backend in karyos-io (P2.3): backend types, a slot pool and queues; a
  `SocketOps` seam with a scripted implementation for tests; a sockets endpoint
  with TX queues, flush and gate, RX, routes, split, reset and retire; and
  `SocketOps` over rustix on Linux and over `std::net` on macOS, where what the
  standard library cannot do is reported as a fallback, never made up.
- Priority lanes (P2.4). A driver aggregate is one registration with up to four
  lane streams (`add_stream` makes a one-lane aggregate), and `AddPublication`,
  `AddConcurrentPublication`, `AddSubscription` and `PublicationClosed` name a
  lane. A persistent deficit round robin (`karyos_protocol::lanes::drr`) drives
  the lane sender over the backend's TX queues and the `AggregateSubscription`,
  which serves one resumable `FrameReader` per lane.
- Guards and abort (P2.10, G-a to G-e2): the guard word and the outcome ring in
  karyos-sys; the guard CnC messages and the client's guard binding with its
  outcome reader, a faulted outcome stream ending the handle with
  `OutcomesLost`; the driver's guard registry (`add_guard`, `close_guard`,
  `reopen_guard`) with an audit ring; guarded local streams, whose walker writes
  the outcome records and whose close seals the stream and aborts open claims; a
  fresh publication incarnation after a reopen, which remote registrations and
  grants name; token buckets for rate limits; and a sender's applied guard
  epoch.
- Benchmarks: receive and receive-duplicate workloads, a scheduled open-loop
  workload, a cleaner comparison, `ipc-ping-pong` and `ipc-throughput` between
  processes (Linux), tracing overhead and Criterion microbenchmarks (criterion
  0.7.0, pinned); and karyos-bench's statistics and decision rules, host
  inventory and environment classification, and workload composition.
- Tooling: `make loom-full` for the slow counters models, `make sim-arch` (the
  simulator sweep natively and under emulated linux/amd64),
  `make unsafe-report`, a fixed seed set for the simulator sweep, and one Linux
  target volume per tree in `scripts/linux-test.sh`.

### Changed

- The enums decoded from evolving wire and record schemas are
  `#[non_exhaustive]`: `karyos-protocol`'s CnC `SubscriberRole`,
  `RejoinPolicyCode`, `RejoinOutcomeCode`, `FallbackReasonCode`, `Command`,
  `ErrorCode`, `Response`, `CutoverState`, `LossPolicyCode`, `CloseReason` and
  `Event`, the admission `Message`, `RegionKind` and `Capability`, and the
  network `Control`, `ControlKind`, `NakReplyReason`, `RttmKind` and `Datagram`;
  `karyos-archive`'s control `ResponseCode`, `ControlMessage`, `RecordingState`,
  `Signal` and `ReplayRate`, the catalog `StopReason` and `FailKind`, the
  segment `EntryKind` and the group record's `Clock`, `Capture`, `Payload`,
  `Freshness`, `EndReason`, `LifecycleKind`, `Loss`, `Operation`, `Outcome`,
  `TimerAction`, `EndOutcome`, `GapReason`, `OverrunOutcome`, `FallbackReason`,
  `GroupRecord` and `Role`; and `karyos-trace`'s `Point`. A downstream `match`
  on one of them needs a wildcard arm. No wire code or format changes: an
  unknown value still decodes to the same typed error. Inside the workspace a
  value a later version decodes is refused, never given another variant's
  meaning: the driver treats a command it does not serve as a protocol
  violation; the C ABI's `karyos_archive_list` refuses a page holding a
  recording state or stop reason it has no code for, with `KARYOS_E_REFUSED` and
  response code 5 (unsupported schema), delivering nothing. `GroupGateway` is
  sealed; `ReplayProvider` gains methods only with default bodies or a breaking
  version. `OnLap`, `Mode` and both `CommitOutcome` stay closed by design.
- `NetworkSubscriptionReady` (CnC `0x8A`) carries the network subscription's
  bound local address, changed in place under admission `VERSION` 2, which no
  release has used: it grows from 3 to exactly 6 words, `client | sequence |
  registration | family_port | address_hi | address_lo`, and any other length is
  refused. `family_port` packs the port (bits 15 to 0), the family (bits 23 to
  16: 0 none, 4 IPv4, 6 IPv6), reserved bits 31 to 24 (zero) and the IPv6 scope
  id (bits 63 to 32; zero for IPv4 and family 0). An IPv6 address fills both
  address words in network order; an IPv4 address sits in bits 31 to 0 of
  `address_lo`, with `address_hi` zero. Family 0 has every other field zero. The
  IPv6 flow information is not carried. The address is what the driver's socket
  reports after the bind; a multicast subscription reports its group address and
  the bound port, not the interface. The `cnc` module docs give two byte
  vectors. For the item 41 API list: `Response::NetworkSubscriptionReady` and
  `karyos_client::Outcome::NetworkSubscription` gain `bound:
  Option<SocketAddr>`, and `karyos_client::Subscription` gains `bound_address()
  -> Option<SocketAddr>` (`None` for a stream subscription). Port 0 stays
  refused in every channel URI; the C ABI is unchanged.
- A network publication whose channel asks for `fc=max` or `fc=tagged:<group>`
  is refused with `DriverError::UnsupportedChannel` (a client's add by URI:
  `ErrorCode::UnsupportedChannel`), instead of running `min` silently: the
  driver parsed the key but never wired it to the sender's membership. `fc=min`,
  what every publication runs, is taken.
- The channel URI enums (`ChannelError`, `Interface`, `Trace`, `FlowControl`,
  `Security`, `ControlMode`, `Destination`, `Media`) and the public error enums
  of the library crates (`karyos-sys`, `karyos-protocol`, `karyos-codec`,
  `karyos-io`, `karyos-trace`, `karyos-driver`, `karyos-cluster` and the
  `karyos` facade) are `#[non_exhaustive]`: a later version can add a URI form
  or an error without breaking a downstream exhaustive `match`. The driver
  refuses a URI form it does not serve as `UnsupportedChannel`, as it does a
  form not wired yet. `karyos_sys::log_buffer::ReadError` stays exhaustive for
  now: the Archive's source classifies each of its variants, and an unknown one
  needs a design choice.
- `ImageAvailable` (CnC `0xC6`) encodes its source address exactly as
  `NetworkSubscriptionReady` (`0x8A`) encodes its bound address, aligned in
  place under admission `VERSION` 2 before its freeze, so the version has one
  address encoding. Its six words stay `stream | registration | image |
  family_port | address_hi | address_lo`; an IPv4 source moves from word 4 to
  bits 31 to 0 of `address_lo`, with `address_hi` zero, and strict decoding
  refuses the old layout. The IPv6 scope id is now carried in bits 63 to 32 of
  `family_port` (it was dropped); the flow information is still not carried. An
  image always has a source, so family 0 is refused. The `cnc` module docs give
  a byte vector with an IPv6 link-local source and its scope. For the item 41
  API list: no public signature changes; `Event::ImageAvailable`'s `source` now
  keeps its IPv6 scope id through the CnC.
- A schedule ring on a driver's local stream is refused.
  `EmbeddedDriver::add_stream` and `add_aggregate`, the client facade's local
  streams, `karyos_driver_add_stream` and karyosd's `--stream` answer
  `schedule_capacity` above 0 with `DriverError::InvalidConfig` or
  `KARYOS_E_INVALID_ARGUMENT`: nothing would release such a ring, which took its
  capacity of timed offers and then back pressured for good. A timed lane is a
  network publication's. A driver configures timed network streams
  (`NetworkStreamDefaults::timed`, at most 8, with a capacity of 0 or a stream
  given twice refused at start; karyosd `--timed-network <stream>:<capacity>`,
  which needs `--network on` and names no `--stream`). A client's network
  publication of such a stream, added by URI, is timed with the default
  schedule; there is no URI key.
  `EmbeddedDriver::add_timed_network_publication_with_clock` is the network twin
  of `schedule_stream_with_clock`, its clock fixed for the publication's life.
  No signature, struct or CnC change. The conformance scenario
  `publication.timed.offer` now runs against karyosd's timed network stream 25,
  with a loopback receiver (feature `remote-driver`): a timed offer is not
  delivered before its time, then is, with the typed refusals as before. The new
  `stream.schedule.refused` covers the refusal on a driver's stream. The
  semantic layer gains `publication.offer_at` (answering its `tx_time`) and
  `until` and `not_before` on `subscription.poll`, and the runner retries a
  remote offer's `not_connected` too. No `Tai` timed lane exists now: the
  network route refuses that domain. The frozen bindings keep their pinned
  suite; their first pin update after the freeze adopts this behaviour and the
  scenario.
- Breaking for 0.1.0-alpha.1 users of the `karyos` facade (c52fcc2d, the
  SPEC §10 publication shape): 13 re-exports moved from `karyos::` to
  `karyos::embedded::`: `Aborted`, `ClaimOutcome`, `ClientClaim`,
  `ClientConductor`, `ClientPublication`, `ClientSubscription`,
  `CommitOutcome`, `Completion`, `ConductorError`, `ConductorPoll`,
  `OfferOutcome`, `Outcome` and `Overrun`. `karyos::Error` is
  `#[non_exhaustive]` and gains the `Offer` and `Subscription` variants,
  so a `match` on it needs a wildcard arm. `EXTENSION_VERSION` now lives in
  `karyos_sys::frame`; `karyos_protocol::frame::EXTENSION_VERSION` still
  resolves through a re-export.
- `karyos-ffi`: each copy of the library draws its own base generation for its
  handles, once, from the address of one of its statics (never 0; no clock or
  process id, so it runs under Miri's isolation). A handle of another copy in
  the same process (two static copies) then normally names a slot at another
  generation and answers `KARYOS_E_CLOSED`, instead of acting on that copy's
  object; a copy cannot tell a foreign handle from a stale one. This defends
  against accidental misuse only, per pair of copies, not per call: equal
  bases, or generation counts drifted apart by the bases' difference, let a
  foreign handle through. A slot's generation counts on from the base,
  skipping 0, and the slot is retired only once it would come back to the
  base, after all 2^32 - 1 generations (it was retired at u32::MAX before).
  The handle's layout and the ABI are unchanged (`handles::tests`).
- The conformance seeding of the `archive-replay` feature waits until
  `"r0"` to `"r4"` are recorded before it pauses (now 50 ms) and
  publishes `"r5"` to `"r9"`. Record times are per recorder duty, so a
  duty that copied all ten messages stamped them alike, and
  `op.replay.stopped`'s 1 ppm replay could end before its stop.
- `make lint-sync` runs shellcheck over `scripts/*.sh` where shellcheck
  is installed (and says so where it is not), so the scripts stay clean.
  The three findings on main are deliberate and now carry their reason as
  a directive: perl's `$ARGV` inside a single-quoted program
  (`check-lint-sync.sh`), a function only the trap calls
  (`sim-arch-compare.sh`, SC2329 and, before shellcheck 0.11, SC2317),
  and Markdown code spans in the report's `printf` formats
  (`unsafe-report.sh`). `package-libkaryos.sh`'s version check is an `if`,
  which shellcheck 0.9 (Debian bookworm, Ubuntu 24.04) also accepts.

- `karyos_subscription_rejoin_state` (F9b) keeps the caller's `size`, as
  `karyos_detail`, `karyos_accepted` and the image change do: it wrote
  the library's 16 back into a newer caller's struct before. The new
  `karyos_subscription_end_state` (F9c) follows the same rule.
- `karyos-ffi`: a child's close (publication, subscription, conflated view,
  Archive connection) no longer answers `KARYOS_E_BUSY` because another call
  holds its client. With the client free it releases the child at once, as
  before; while another call holds the client, on another thread or by a
  callback, it ends the child at once (the close answers `KARYOS_OK` and the
  handle is stale) and the client releases it at its next call or its close. A
  client with no further calls holds the released resources (a publisher slot,
  lanes, streams) until its next call or close. `KARYOS_E_BUSY` and
  `KARYOS_E_REENTRANT` from a child's close now mean the child itself is in use,
  so binding destructors, which may not retry, no longer leak sibling handles
  destroyed on several threads at once (found by karyos-cpp's C-THREAD-RULES
  test). `karyos.h` Threads and the four closes' docs state it
  (`api::client::tests`, `abi::tests::threads`).

- The conformance suite gains format 2 (ADR-0073), beside format 1, whose 27
  scenarios run unchanged; format 1's `karyos_driver_start` now defaults its
  `idle_strategy` to the ABI's declared default, `KARYOS_IDLE_YIELD_THEN_SLEEP`
  (3), in place of `KARYOS_IDLE_YIELD` (1), which changes no result. Format 2
  adds a semantic layer of ops that a binding runs through its public API, with
  a binding's close rules (a second close is `ok`; an op on a closed object or a
  closed parent's child answers `closed`) and outcomes named by header status;
  values from -2^63 to 2^64 - 1; `since`, the binding SPEC step that requires a
  scenario; `feature`; bounds on files, lines, steps and variables; and a
  pinning line with the SHA-256 of the suite and header and the core's identity.
  The reference runner runs the ops through a semantic adapter over the C ABI
  and reports each scenario passed, skipped, unsupported or later. Twelve
  scenarios: the claim semantics every binding shares (BIND-S3: one outstanding
  claim, a retryable commit that keeps the claim, a one-shot claim that leaves
  none), the close rules, concurrent publication, conflated views, outcome
  streams and the clocks.
- `karyos-ffi`'s default idle strategy is `KARYOS_IDLE_YIELD_THEN_SLEEP`
  (ADR-0066): `karyos_client_options_init` now fills it in place of
  `KARYOS_IDLE_YIELD`, and `karyos_driver_start` takes it. The new
  constant (3) yields for the first 64 consecutive idle waits, then sleeps
  1 ms per wait, and starts again after a wait that found work; the driver
  thread uses the agents' own `YieldThenSleep`. Busy-spin stays an
  explicit choice.
- `karyos_client::Context`'s default idle strategy is the new
  `IdleStrategy::YieldThenSleep` (ADR-0066), in place of `Yield`, so a
  client's control-call wait yields for 64 idle waits and then sleeps
  1 ms per wait. The ABI's default is the facade's. `BusySpin`, `Yield`
  and `Sleep` stay explicit choices.
- `karyos.h` states the ABI version rule in place of "a different major is
  incompatible": call `karyos_abi_version` first, before any other call and
  before using newer symbols or layouts; the ABI version is independent of the
  workspace version; before 1.0 a caller accepts exactly the `0.y` it targets
  with at least its minimum `0.y.z`.

- The alpha.2 public API audit's refresh (2026-10-20):
  `karyos_archive::source::Rejoin` is `#[non_exhaustive]`, so a match outside
  karyos-archive needs a wildcard arm; hosts still build every variant.
  `ClientSubscription::poll_taking` documents its errors.
- `karyos-ffi` stream options take a concurrent publication mode:
  `KARYOS_PUBLICATION_CONCURRENT` with `publishers` (1 to 255), in an
  88-byte `karyos_stream_options` read by prefix (64, 80 and 88 bytes are
  accepted; a size between two layouts, or a nonzero `reserved`, is
  `KARYOS_E_INVALID_ARGUMENT`). An exclusive stream takes `publishers` 0.
  A C caller's embedded driver can now host a concurrent stream, so
  concurrent handles and an Archive's request stream are reachable from
  the C ABI alone. The driver's default refuses a concurrent stream on
  aarch64 without LSE atomics (ADR-0012). Conformance gains
  `publication.concurrent` and the 88-byte layout.
- `karyos-ffi`'s Miri profile: `crates/karyos-ffi/MIRI.md` maps every unsafe
  site class of `src/abi.rs` and the test support to the test that runs it under
  Miri, and lists what Miri does not cover. Under Miri the tests' driver threads
  and waits sleep instead of yielding, so a driver test takes about a minute
  instead of an hour; driver integration tests that add no unsafe site are
  native only (`driver integration; covered natively`). A PR touching
  `src/abi.rs` or the test support runs Miri per that file on its head.
- karyos-tools: `replay::HELP` is replaced by `replay::help(command)`,
  which names the command the diff was invoked as (`karyos-replay diff` or
  its alias `karyos-tools replay diff`; H5, #521).
- Every publication of a conflated stream checks its key against the
  stream's table before it appends (#523; F7b-2a, F7b-2c-2): an offer or
  claim with a key outside the table, or a value larger than its
  capacity, is refused (`ClientError::Conflation`), whether the
  publication is the driver's own, granted through the command ring of a
  driver in the client's process, or taken by a client attached to a
  driver in another process. Until now only the driver's own publication
  checked; the others appended such a message and the driver's feeder
  dropped it from the conflated view and counted it as a rejected key.
  The low-level `ClientPublication` taken from a grant was the earlier
  route to that gap. The feeder still counts what a raw writer appends.
  - The table's shape travels with the log buffer: words 19 (keys) and 20
    (largest value) of its configuration block, written by the driver
    before the buffer is shared (`LogBuffer::with_conflation`,
    `ConflationShape`, `LogBuffer::conflation`), and read back at attach.
    `ClientPublication::new` and `ClientConcurrentPublication::new` bind
    it, so in-process and remote grants bind it the same way.
  - The check is `ConflationShape::validate_publication`: a publication
    holds the shape alone, not a table configuration with a journal it
    does not have. `ConflationConfig::shape` gives a configuration's, and
    `ConflationConfig::validate_publication` delegates to it.
  - The log buffer's `LAYOUT_VERSION` goes to 5; regions of versions 1 to
    4 are refused at attach. A configuration block with half a shape, or
    one the buffer cannot carry, is refused (`SysError::InvalidRegion`);
    `LogBuffer::with_conflation` refuses such a shape with the new
    `SysError::InvalidConflationShape`.

- karyos-archive's `client::connection` (F9-0): a requester's control streams to
  an Archive over a facade client. `ArchiveConnection::open(&mut client,
  ControlStreams::new(requests, responses))` takes a concurrent publication on
  the shared request stream and an optional subscription, rejoining at the head,
  on the shared response stream (`karyos:ipc`): a requester that stops reading
  is lapped instead of holding back everyone's answers. It answers `OpenError`
  naming the stream it could not take, and a failed open removes the publication
  it took. `into_transports` gives the `Requests` and `Responses` an
  `ArchiveClient` or a `RecordingLister` takes; `close`, `Requests::close` and
  `Responses::close` remove them from the client, and
  `RecordingLister::into_transports` gives them back. An answer longer than the
  caller's buffer is dropped and counted (`Responses::oversized`). The
  management agent's catalog uses it in place of its private adapters, and so do
  `karyos-catalog list --live` (H4b) and `karyos-replay start` (H6). It is
  public API.
- A replay waits for its target's first reader (H2b), so a requester that
  subscribes after the `Replay` answer reads it from its first position.
  - karyos-archive's `ReplaySink` gains `ready()` (true by default). The
    agent steps nothing into a sink that is not ready.
  - A replay still not ready past the new `AgentConfig::attach_deadline`
    (default 5 s) ends with the new `ReplayOutcome::NoSubscriber`,
    having written nothing. `ControlServer::unattended()` counts these.
  - karyos-driver's `ReplayFeed::has_subscriber()` reports whether the
    target has an attached reader. `DriverHost`'s sink is ready once it
    has one, and an unattended replay's target is retired at once,
    without the linger, and logged with its replay id.
  - Version 1 has no replay-end message: the requester sees only that
    the target retired unjoined (`ArchiveClient`: `Unavailable`). A
    typed end signal is a version 2 message, for later.

- The Archive's host over a driver (H2).
  - `karyos_tools::archive::DriverHost<T>` implements
    `karyos_archive::server::ArchiveHost` over an `EmbeddedDriver<T>` it
    owns. It opens a recording reader for each `StartRecording` of an
    active local stream, found by its key (refused as "no such stream"
    otherwise), and a replay target for each replay.
  - A replay that ended keeps its target for the host's replay linger
    (`with_replay_linger`; default 5 s, an interim value) before `finish_ended`
    finishes and retires it. `finish_all_ended` is for shutdown, and
    `into_driver` returns the driver.
  - karyos-archive's `ControlServer::shutdown_into_host` stops the agent
    and hands the host back. karyos-driver gains
    `EmbeddedDriver::stream_handle(StreamKey)`, the active local stream of
    a key (never a network image, nor a retiring stream).
  - The host's loop is the driver's duty, `ControlServer::duty`, then
    `finish_ended`. Tests run on a heap driver, and on Linux on a
    shared-terms one.
  - A subscriber that joins a target after the Replay answer does not
    read the replay yet: the sink waiting for a first subscriber comes
    in H2b.

- `EmbeddedDriver::recording_reader` works on every driver, not only a heap one:
  `RecordingReader` is generic over the driver's terms
  (`RecordingReader<T = HeapTerms>`, its parts `LaneReader<T>` and
  `GenerationLink<T>`), so `karyosd`'s shared-terms driver can record its
  streams (H1). Code that names `RecordingReader` keeps its meaning through the
  default.

- A timed lane's handle is granted over the control path (T-x2):
  `AddPublication` no longer refuses a timed lane. A `Monotonic` lane goes to a
  remote client only when admission proves it in the driver's time namespace,
  and is otherwise `InvalidPublicationMode` with the client's `TimeNamespace`
  code as the detail; a `Tai` lane goes to any client. The driver writes the
  lane's binding into the schedule ring when its settings are fixed (the first
  handle, the sender, or a grant). The client reads it when it takes the handle:
  `ClockDomain::code` and `from_code`, `ScheduleOptions::binding` and
  `from_binding`, and `schedule::ring_binding`; a binding it does not know is a
  protocol error. The sender posts `AgentEvent::ScheduleViolated` once per
  breached lane; the conductor seals the lane with `ScheduleViolation` if the
  report names the live incarnation (a stale or over-bound report counts in
  `schedule violations dropped`), counts it in the new driver counter
  `schedule violations`, logs a `ClientProtocolViolation` error, and has
  admission retire a remote holder as faulty. `LatePolicy` and the T-x1 interim
  stop are unchanged.

- The schedule ring's sender trusts no word its publisher writes (TT-6; T-x1).
  The ring's header grows from three words to eight, with the lane's binding in
  words 3 to 6 (domain, `max_horizon`, `lateness_tolerance`, flags; bit 0
  `cancel_on_deadline`): `schedule_ring::write_binding` for the driver at
  creation and `schedule_ring::binding` for the publisher. The log buffer's
  `LAYOUT_VERSION` moves from 3 to 4, so version 3 regions are refused at
  attach. `ScheduleReader` keeps its head privately and copies each entry once,
  sized to the ring's capacity at attach (16 bytes per entry); it checks the
  tail copy (at least the last, at most `head + capacity`) and each entry's time
  (at least the last, at most the sender's `now + max_horizon`), and serves
  rewinds from the copies. `peek` takes `&mut self`, `now` and `max_horizon`;
  `advance` takes no ring. A breach is the new `ScheduleError::Violation`, for
  good. `SealReason` gains `ScheduleViolation` (code 9), a gate reason reported
  as `Gated`. `LatePolicy` gains `max_horizon`, and `ScheduleConsumer::new`
  takes it. The driver's `ScheduleConsumer` checks each entry's position against
  its frame: a frame its entries contradict (`CorruptTerm`) is the publisher's
  breach too, and every later frame is refused as a `Violation`. Interim until
  T-x2: the sender counts a violation once in `schedule_faults` and stages
  nothing more of the lane; T-x2 seals it with `ScheduleViolation` and retires
  the client.

- A guard command's "no operator" word is `NO_OPERATOR` (`u64::MAX`), not 0, so
  root's uid 0 is audited as an operator (M10b; a defect of M10a that M10b's
  end-to-end test found as root), changed in place under admission `VERSION` 2.
  Any other word is a 32-bit uid; a word above `u32::MAX` but `NO_OPERATOR` is a
  reserved value, refused in both directions. `ClientConductor::guard_close` and
  `guard_reopen` (and `RemoteClient`'s) take `operator: Option<u32>`. The audit
  ring's readers tell an operator by `requester_kind` 2, never by word 8, which
  holds 0 for root.

- `GuardClose` and `GuardReopen` carry the operator a client acts for and a
  parameters digest (M10), in place under admission `VERSION` 2, which is
  unreleased: `GuardClose` grows from 3 to 5 words and `GuardReopen` from 4
  to 6. `karyos_protocol::cnc::guard_parameters` is the digest, 64-bit FNV-1a
  over the guard, the expected epoch (0 for a close), the operation id and
  the operator uid, then the operator's reason: a correlation aid, not a
  security digest. The driver audits a command naming an operator as
  `Requester::Operator { client, uid }`, and every record carries the digest
  (`AuditRecord::parameters`). The guard audit ring of `karyos_sys::diag`
  writes the operator uid and the digest into words 8 and 9 of its record,
  zero before, with `requester_kind` 2 for an operator; the record's size is
  unchanged. The management agent's guard feed and API v1's JSON append
  `operator` and `parameters` to each record.

- karyos-client's public enums and report structs are `#[non_exhaustive]` before
  alpha.2, so later minor releases can add variants and fields: errors
  (`ClientError`, `SubscriptionError`, `OfferError`, `ConductorError`,
  `MergeError`, `MergeFailed`, `HandOverError`, `AttachError`), outcomes and
  reports (`OfferOutcome`, `ClaimOutcome`, the concurrent ones,
  `SubscriptionPoll`, `ImageStop`, `MergePoll`, the aggregate's polls,
  `LinkStatus`, `LeaseState`, `ViewClosed`, `ReplayStatus`, `ReplayUnavailable`,
  the conductor's `Outcome`, `Completion`, `Fetchable*` and the counter
  snapshots) and inputs users build from variants or `Default` (`IdleStrategy`,
  `RejoinPolicy`, `Secondary`, `ClockDomain`, `Request`, `ScheduleOptions`,
  `ConflatedLimits`). A match outside the crate needs a wildcard arm, and a
  struct is built from `Default`: `ScheduleOptions` gains `with_domain`,
  `with_max_horizon`, `with_lateness_tolerance` and `with_cancel_on_deadline`.
  `ScheduleCounters` and `link::Capability` stay as they are, closed driver
  contracts.
- `karyos-client`: `PollSummary`, `PollError`, `Overrun`, `Skipped`,
  `Aborted`, `RejoinOutcome`, `SecondaryOutcome` and `ReplayFallbackReason`
  are `#[non_exhaustive]`. `PollError::new`, `Overrun::new`, `Skipped::new`
  and `Aborted::new` build them; `PollSummary` is built from `Default`.
- `karyos-archive`'s public enums and report structs are `#[non_exhaustive]`, as
  the public API audit lists them (`ControlMessage`, `GroupRecord` and `Role`
  aside). The inputs gain constructors and are `#[non_exhaustive]` too:
  `StartGroup::new` (with `with_new` and `with_checkpoints`), `NewGroup::new`,
  `GroupCheckpoints::new` (with `with_reopen_hold`), `StartRecording::new`,
  `StartReplay::new`, `PrepareReplay::new`, `HostRecording::new`,
  `CaptureConfig::new`, `JournalConfig::new`, `ClaimCommit::new`,
  `SourceIdentity::new`, `CursorConfig::new`, `ReplayConfig::new` (with
  `accepting_manifest`), `GatewayConfig::new` (with a `with_*` per field),
  `replay::gateway::Archive::new` and `replay::reference::Recording::new`. A
  rejoin outcome the Gateway has no record code for is refused
  (`GatewayError::UnknownOutcome`), never recorded under another's code.
- `karyos-client`: `ReplayRequest`, `link::Owner` and `link::HandOverEntry`
  are `#[non_exhaustive]`, built through constructors: `ReplayRequest::new`,
  `Owner::new` and `HandOverEntry::new` (`with_generation` and
  `with_publication` add its optional parts).
- A fenced `async` recording that resumes after a lap rejoins its stream at the
  head. The host gives `source::Following::rejoining(reader, link, base, hook)`
  a `RejoinHook`: fenced, the source asks it for a new optional member of the
  current generation, admitted at its head with
  `recording_reader(stream, Role::Optional)`, and answered `Rejoin::Joined` (the
  reader, its link, its base and the lease, kept as the source's guard),
  `Rejoin::Waiting` or `Rejoin::Refused`. The hook runs on the Archive's thread,
  so a host whose driver runs elsewhere answers through a channel. The recorder
  reads the new `Frames::Rejoined { from, to }`, records the plain gap
  `[from, to)`, marks the recording incomplete and goes on; `Duty::rejoined`
  reports it and `ArchiveHandle::rejoined_recordings` counts it, beside
  `fenced_recordings`. A refused rejoin, a source without a hook, `stop` and
  `required` recordings end at the seal, `Lapped`, as before; a rejoin anywhere
  else is `Invalid::Rejoin`. No driver API or segment format change.
- Recordings follow a mapping cutover. The driver makes a recording reader a
  member of the stream's cutovers: `recording_reader` registers it with a
  `GenerationLink` (`RecordingReader::link`, `RecordingReader::base`;
  `RecordingReader::into_following_parts` returns the reader, the link, the base
  and the lease), and a cutover offers it a successor recording cell
  (`Successor::Recording`) under a subscriber's progress lease.
  `DriverError::RecordingCutover` is removed: a recorded stream can be
  reconfigured. **A host must wire its recordings through `into_following_parts`
  and `Guarded::new(Following::new(reader, link, base), lease)`**: a reader
  taken with `into_parts` has no link, so where a cutover used to be refused, it
  now fences that reader and its recording ends at the seal, `Lapped`.
  `karyos-archive`'s `source::Following` reads stream positions across the
  cutovers: at a seal with a successor it moves and reports `Frames::Cutover`,
  and the recording goes on with no gap; fenced, it reports `Frames::Fenced`,
  and the recording ends at the seal, incomplete, with `StopReason::Lapped`,
  whatever its lap policy. `Duty::fenced` reports it and
  `ArchiveHandle::fenced_recordings` counts it; the segment format does not
  change. `karyos-client` exposes `GenerationLink::next` and its `Next` outcome
  (`#[non_exhaustive]`), and `karyos-sys` adds `SenderRead::buffer` and
  `SenderRead::sealed_with_successor`.
- `karyos-archive` recovery gains a dry run: `SegmentStore::verify`
  returns a `RecoveryPlan` (the kept segment as a `KeptSegment`, the
  `Cut`, and each removed segment as a `DroppedSegment` with its
  `DropReason`) and changes nothing on disk. `SegmentStore::recover`
  applies the same scan's plan, so the two agree. A last segment with a
  valid index header, no entry and no data file (its creation cut short
  by a crash that kept only the index's directory entry) is now removed,
  as `DropReason::CreationGap`, instead of refused with
  `BadHeader { Incomplete }`; before the last segment it is still
  refused.
- A remote client's registrations are capped at `max_exports_per_client`,
  as its ledger's grants were before. Every add that makes a
  registration counts: `AddPublication`, `AddConcurrentPublication`,
  `AddSubscription`, `AddImageSubscription` and a conflated view; past
  the cap each is refused with `ResourcesUnavailable`, and the client
  stays served. A remote registration whose last grant ended (detached,
  or ended unsent) is reclaimed, so a client that only drops its handles
  never reaches the cap that way; a later `RemoveSubscription` or
  `RemovePublication` of a reclaimed registration answers
  `UnknownRegistration`, which the client facade ignores.
- `Client::remove_subscription` removes a subscription as
  `Client::remove_publication` removes a publication: a `karyos:ipc` one
  at the driver, a `karyos:udp` one with every image it reads. A removal
  that cannot be sent drops the handle and is counted:
  `Client::subscription_releases_failed`, as the facade counts every
  image handle it lets go of whose removal could not be sent.
- A publication released through the client facade whose removal cannot
  be sent (the command ring full, a handle another connection issued, a
  closed link) is counted: `Client::publication_releases_failed`. The
  handle is still dropped; in process that ends its lease, and for a
  remote client the driver keeps the publication, with no EOS, until the
  client ends. The doc-hidden `Connection::release_publication` returns
  whether the removal was sent (#402 review P3).
- The `replay` rejoin with an Archive (phase 3, A6c; SPEC.md §4).
  `karyos_client::ReplayRejoin` wraps a subscription: on an overrun the
  live reader rejoins at the head, the poll reports the overrun as
  `RejoinOutcome::Replaying`, and a `ReplayProvider` is asked for the gap,
  across polls; its replay is merged in (`LiveMerge`), and the poll on
  which the merge settles reports `RejoinOutcome::Replayed { cutover }`.
  With no replay, or a merge that fails, the secondary policy applies and
  the poll reports `ReplayFallback` with the reason, which gains
  `RecordingBehind`, `Refused` and `MergeFailed`. Each overrun is
  reported to the driver once, when it resolved; a gap given up first,
  when the rejoin is dropped or its live reader taken back
  (`into_live`, which gives back the reader's own policy and loss
  reports), is reported as `Withdrawn`. The loss report gains the outcome
  code `Replayed` (5, with no reason) and the reasons 4 to 7, in place
  under admission version 2, and the driver counts `overruns replayed`.
  A plain `RejoinPolicy::Replay`, with no provider, still falls back with
  `NoArchive`. `LiveMerge::is_settled` tells when a merge is done.
- The Archive's client (phase 3, A6b-2).
  `karyos_archive::client::ArchiveClient` is a `ReplayProvider` over the
  Archive's control streams (`ControlRequests`, `ControlResponses`): asked
  for a source's range, it lists the recordings, picks one of that
  publication and incarnation that covers the range, asks for a replay of
  exactly that range onto `ClientConfig::target_stream_id`, and hands out
  the target's subscription, which the host's `ReplayTargets` finds at the
  replay id's low 32 bits. It never blocks; a recording behind is listed
  again until `ClientConfig::deadline`. No replay comes as `NoRecording`,
  `RetentionShort`, `RecordingBehind` or `Refused`. A handed-out replay
  stops by `StopReplay`, queued when the request stream has no room, and
  a replay withdrawn before its answer is stopped when the answer comes:
  `ArchiveClient::duty` does this while no replay is asked for, and a
  cancel or a drop sends what it can. The constructors refuse a target
  channel no request can carry (`ConfigError`).
  `karyos_client` re-exports `PublicationIdentity`, which its merge API
  names.
- The Archive's `RecordingDescriptor` (control schema 1, A6b) carries
  the recorded publication's identity (`source`, a `SourceIncarnation`)
  and, while it records, the position written so far
  (`RecordingState::Recording { written, .. }`): its block grows from 70
  to 110 bytes, and a descriptor whose `written` lies below its start or
  away from its stop is refused. A replay target's session id is the
  replay id's low 32 bits (`server::replay_session_id`), and
  `ArchiveHost::open_replay` takes the replay id. A prepared replay whose
  sink never comes is dropped after `AgentConfig::prepared_timeout`, so
  it no longer holds a replay's slot.
- The live merge (phase 3, A6a; SPEC.md §8.2).
  `karyos_client::LiveMerge` merges a `Replay` of a recording into the
  live subscription of the same publication at an explicit cutover: the
  live reader's position when the merge is made. Below it the replay's
  messages are delivered, from it the live reader's; the replay's
  duplicates are dropped by position, and the live reader's first message
  must match the replay's there in position and length. Every
  disagreement is a typed, final `MergeError`: an epoch change (another
  publication or incarnation), a reader of another lane than 0, a replay
  short of the cutover, a message or term padding across it, a replay or
  live reader lapped. A required live reader keeps a first message that
  disagrees pending, for `into_live`. A gap in the
  recording below the cutover is reported as the replay's local gap. A
  replay stops through its `ReplayStop` at the cutover, on failure and on
  drop. `ReplayProvider`, which the Archive's client implements, hands out
  replays without blocking (`ReplayStatus`, `ReplayUnavailable`).
- The Archive is controlled over streams (phase 3, A5c).
  `karyos_archive::server::ControlServer` reads A1's requests from a
  `RequestSource`, serves them with the agent and answers on a
  `ResponseSink`, one request at a time and only once the last one's
  answers are out; a start is signalled with its request's correlation
  id, a stop or failure with 0. It never blocks: it posts its commands
  (`ArchiveHandle::post_start`, `post_stop`, `post_list`,
  `post_prepare_replay`, `post_attach_replay`, `post_stop_replay`) and
  answers when the agent's `Posted` answer arrives, in a later duty. What
  touches the driver stays with the host behind `ArchiveHost`: a
  recorded lane's reader, and a replay's target stream, opened only once
  the agent prepared the replay and found its range readable. The agent
  runs replays into the host's `ReplaySink`s, after its recorders and
  within one shared budget per cycle (`AgentConfig::replay_budget`),
  taking a step back (`ReplaySource::hold`) when a sink has no room, and
  describes and stops them (`ArchiveHandle::describe`, `replay`,
  `stop_replay`). Recordings and replays at once are capped
  (`max_recordings`, `max_replays`; `AgentError::Full`, counted by
  `ArchiveHandle::refused`), and so are the server's waiting signals
  (`ServerConfig`, `dropped_signals`). A replay's end comes on its own
  queue (`ArchiveHandle::try_replay_ended`), and `Event::Failed` carries
  the position written. The catalog becomes version 3: a recording's
  `Started` keeps the recorded stream's lane, initial term id and mtu
  (nonzero), which its replays need, and the source's incarnation
  (`SourceIncarnation`: the driver id, registration and incarnation of
  the publication recorded), which a live merge matches
  (`StreamFormat`).
- A guarded network publication's outcome records come from its sender gate's
  submissions, not from the commit. A message is `Submitted` once a backend took
  every frame of it, `Unknown` when it may have left whole unproven (an
  `Unknown` report, an exposure a reset or a removal cut short, a position no
  first send took, which a reliable lane may still repair, or a later route's
  submission above a position that never left), and `Aborted` when it never
  leaves whole: its last frame was not sent when a close, a removal or a network
  close ended the lane (a partial fragmented message is `Aborted`, as the
  design's kind table says). A message's reservation is therefore released at
  its network submission, so the publisher holds at most `C_m` messages
  committed and not yet sent: the effective window is the smaller of the
  receivers' and `C_m` messages. The close acknowledgement's `positions` are
  each lane's prefix-closed frontier: below it every message was handed to a
  backend or is reported `Unknown` (before, the highest position submitted,
  which an unproven or skipped one could sit below). `GateHead` gains `start`,
  and `GuardGate::reopen` and `reopen_route` take whether the lane is rewound;
  `GuardSpec` gains `frontier`. Code that names every field in a struct literal
  must add them.
- `RouteCounters` (`karyos-io`) and `PathCounters` (`karyos-driver`)
  gained the public fields `datagrams` and `bytes` (rp-w9). Neither
  struct is `#[non_exhaustive]`, so a struct literal that names every
  field must add them. Both count the lane sender's first sends of DATA
  only, catch-up copies included: repairs (`repair_route_counts`),
  PATH_HB and other controls, and `Flushed::Unknown` are not in them.
- An Archive replay's target stream (phase 3, A5b).
  `EmbeddedDriver::replay_target(ReplayTargetConfig)` makes a one-lane
  image with local gaps, joined at the replay's first position and
  exposed as an aggregate of lane streams as a network image is (n3), on
  the heap or, on an IPC driver, in a region with a fresh id. Its
  `ReplayFeed`, the image's only writer, takes a recording's whole frames
  and PAD or ABORTED records at their recorded positions, each frame's
  session and stream ids written as the target's, and seals a lost range
  as a local gap (`GapReason::RangeUnavailable`); a term not ready yet is
  offered again later. `EmbeddedDriver::finish_replay` seals the target
  with `EndOfStream` when the feed reached the replay's end, else
  `ImageRetired`. Only lane 0 is replayed (`DriverError::ReplayLane`).
  The `EndOfStream` and `ImageRetired` docs now cover a replay's end.
- The Archive's control messages, version 1, written by hand (phase 3,
  A1; ADR-0036). `karyos-codec` becomes the runtime of the minimum v1
  schema: checked little-endian reads and writes, a 12-byte envelope
  (schema, template, version, block length, message length written
  last), top-level groups, bounded bytes and UTF-8, and a typed
  `CodecError`; it drops its unused dependency on `karyos-protocol`.
  `karyos_archive::control` holds the five requests and three responses
  of schema 1, validated whole on decode and encoded into the caller's
  buffer without allocating; an encoding that fails leaves no message
  in the buffer, not even an earlier one.
- An Archive recording is read back for replay (phase 3, A5a).
  `karyos_archive::replay::ReplaySource` reads a recording's range
  without changing it, through read-only files (`Disk::open_read`):
  whole frames, fills and gaps in order, from a frame boundary to the
  last whole frame below the range's end, the end clamped to what the
  recording held at open. No byte goes out before its entry's CRC holds:
  an entry not delivered whole in one read is first read whole through
  the buffer, its CRC and frame lengths checked. A segment missing inside
  the range is an error, never the recording's end. It paces at full
  speed, as recorded or scaled (`NonZeroU32` parts per million). The
  segment index becomes version 2: each entry carries its record time
  (the Archive's write time on its monotonic clock, 0 when unknown),
  stamped by `SegmentStore::stamp` each recorder duty; a paced replay of
  entries without one is refused, and a version 1 index is foreign: an
  archive directory where an earlier build left a recording open fails
  every agent start, since each start's settle recovers that recording.
  A replay's error is final.
- The driver hands an Archive recording a lane's reader (phase 3,
  A4c-2). `EmbeddedDriver::recording_reader(stream, role)` admits a
  reserved required or an optional cell and returns a `RecordingReader`:
  the reader and a lease on its stream, so a removed stream lives until
  its seal is positioned and read; while it lives the stream refuses a
  cutover (`DriverError::RecordingCutover`), since the reader follows
  one mapping. `karyos_archive::source::Guarded`
  keeps the lease with the reader and drops the reader first. The host
  wires the two (SPEC section 14); `karyos-sim` records driver streams end
  to end.
- `karyos-bench` measures the Archive's write and sync cost on a real disk
  (phase 3 follow-up): `archive-append` appends to a segment store that
  never syncs, `archive-sync` syncs after every append. They run only
  when named with `--workload`, in a removed temporary directory or under
  `KARYOS_BENCH_DIR`. Their records name the directory, its filesystem,
  the policy and whether syncs are `F_FULLFSYNC`, and compare only under
  the same host and filesystem; no gate reads them.
- A recording reads a lane's log through the network sender's read
  capability (phase 3, A4c-1). `SenderRead::for_recording` admits a
  reserved required cell (a `required` recording) or an optional one (an
  `async` recording), and `SenderRead::rejoin_at_head` moves a lapped
  optional reader to the reserved head, a block boundary, as a lapped
  optional subscription rejoins. `karyos-archive` implements its
  `FrameSource` for `SenderRead`: a copy is padded to its frames' 32-byte
  stride, so the segment holds the frames where the log does; a lap is
  recorded as a gap up to where the reader rejoins, and a source busy at
  the rejoin is retried on a later duty.
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

- Admission protocol `VERSION` 2, still unreleased and changed in place since,
  so a client and a driver of mixed builds fail with `IncompatibleVersion`. The
  wire and karyos-sys region kinds map through one table.
- Layout versions: the log buffer's `LAYOUT_VERSION` 2 gives the seal word's bit
  61 to the successor mark, and the seal position narrows to bits 0 to 60;
  counters regions move to layout version 2. Regions of version 1 are refused at
  attach.
- The default broadcast capacity goes from 16 KiB to 32 KiB, since
  `ConflatedReady` raised the largest response to 64 bytes.
- The driver's arithmetic is checked where it saturated (#157; SPEC.md §14):
  the duty cycle's and the admission step's work counts
  (`DriverError::WorkCountOverflow`), gauge sums, join and sampled positions,
  and the trace journal table. An overflow counts in `counter overflows`.
  Elapsed times use `age_ns`, so a clock that steps back delays a deadline and
  never fires it early.

### Fixed

- A slow optional receiver no longer holds a reliable network publisher. The
  sender's registered position, the publication's limit, follows only what was
  submitted and what the required receivers consumed (SPEC.md §4, "Sender
  position"). A separate retention hold, a new log buffer cell state
  (`CELL_SENDER_HOLD`, 11) that holds the floor and never bounds the limit,
  keeps the floor at `sent - retransmit_window` lowered by the required
  receivers (SPEC.md §4, "Retention floor"; §6). So a counted receiver's hole
  stays repairable: a lone unicast receiver, or the slowest under `min`. Under
  `max`, an optional receiver's hole below the floor is answered
  `RANGE_UNAVAILABLE` and its image closes as unrecoverable. `retransmit_window`
  is a driver setting (`RepairConfig::retransmit_window`) of half a term by
  default and at most; no URI key sets it yet. Each reliable lane takes one more
  registry cell, and a full registry refuses the publication with
  `DriverError::RetentionHoldUnavailable`. A reliable endpoint reset still
  resends at once what the receivers had not consumed: the reader rewinds to a
  restart position between the hold and the registered position, from every
  receiver's consumption. The cell state is in place under the unreleased
  layout.

- A timed lane on a driver's IPC stream wedges, and the docs now say so:
  only a network sender releases schedule ring entries, so a
  `karyos_driver_add_stream` (or `EmbeddedDriver::add_stream`) stream
  with `schedule_capacity` N takes N timed offers, then answers
  `BACK_PRESSURED` for good, whatever its subscribers read (found in
  karyos-dotnet B2a). Timed lanes are meant for network
  publications. karyos.h, `LogBufferConfig::schedule_capacity`,
  `offer_at`, `offer_at_on` and `schedule_stream` state it, and that a
  timed lane answers `INVALID_SCHEDULE` to a plain offer, an offer with
  options and a claim's commit. Refusing `schedule_capacity` on an IPC
  stream follows once a karyosd timed scenario exists.

- A stream configured `allow_unconnected` (`StreamConfig`,
  `karyos_stream_options`) now grants it to every publication an in-process
  client adds, exclusive or concurrent, as the driver's own handles already got
  it (SPEC.md §4). The driver had used only the client's request, which the
  client facade always sent without it, so a C caller's offer on such a stream
  answered `KARYOS_E_NOT_CONNECTED` until a subscriber attached (found
  in the .NET binding, B1b). A remote (karyosd) client gets it too,
  from its grant: bit 16 of a manifest record's word 6 says the stream allows
  offers with no subscriber, valid only with an exclusive or concurrent
  publication's capability and reserved otherwise. This is in place under the
  unreleased admission version 2, so a version 2 client built before it refuses
  such a grant rather than ignore the policy.
  `karyos_protocol::admission::Record` gains `allow_unconnected`.

- `karyos-ffi`, memory safety (F-48; found by an older-header run): every
  `karyos_*_init` wrote the whole current struct, so a caller built against an
  older header was overrun. `karyos_subscription_options_init` wrote 40 bytes
  into the first header's 16-byte struct. Interim fix:
  - each init is now a `static inline` in `karyos.h` that calls a new
    exported `karyos_*_init_sized(options, sizeof *options)`, which fills
    at most the caller's size and sets `size` to the bytes written;
  - the exported `karyos_*_init` symbols, which binaries built against
    an older header call, fill only the struct's ABI 0.1.0 size;
  - a growing struct needs only its leading `uint32_t` aligned: the
    first `karyos_subscription_options` (four `uint32_t`, aligned to 4)
    was refused as misaligned.
  Binaries built against a 0.1.0 header after the stream or subscription options
  grew must be rebuilt against 0.1.1: the legacy symbol gives them the 0.1.0
  prefix, so the newer fields they set afterwards (the conflation table,
  publishers, an Archive rejoin) are not read. Capping the legacy symbol higher
  would overrun binaries built before those fields. The ABI version moves to
  0.1.1, so a binding states 0.1.1 as its minimum and refuses an unfixed library
  at bootstrap. The `abi.version` scenario no longer pins the patch.
  `karyos.h`'s Rules state the init rule for every later growth.

- `karyos_driver_stop` and `karyos_driver_close` of a started driver
  whose idle strategy is `KARYOS_IDLE_SLEEP` waited out the thread's idle
  sleep, which is unbounded: with `sleep_ns` near `UINT64_MAX` they never
  returned once the thread had gone idle. The Go binding's
  `FuzzDurations` seed hung its Linux gate this way. The thread now parks
  for its idle sleep, and a stop or a close unparks it after asking it to
  stop, so neither waits on any idle strategy
  (`no_idle_strategy_holds_a_stop_or_a_close`).
- `a_call_on_a_busy_spinning_driver_waits_for_one_cycle` failed once at
  a load of 16 ("a call waited through 3 cycles"): a caller preempted
  between reading the thread's cycle count and announcing itself counted
  cycles the thread ran before it could see the caller. The count now
  starts after the announcement, so the bound of 2 holds at any load.
  Test-only code in `api/driver.rs`.
- `karyos_driver_add_stream_with` answered `KARYOS_E_SYSTEM` for a
  `schedule_capacity` the driver refuses: not a power of two, above
  `1 << 20`, or on a concurrent stream (TT-1, GC-7). It now answers
  `KARYOS_E_INVALID_ARGUMENT`, as for the other stream options, and
  `karyos.h` states the rule. The Go binding's fuzz test found it.
  The driver's own refusal of a schedule capacity or a publication
  mode also maps to `KARYOS_E_INVALID_ARGUMENT` now, so a rule the
  options check misses is not reported as `KARYOS_E_SYSTEM` either.
- `make libkaryos` failed on main after #555 ("no format version in
  conformance/FORMAT.md"): the package script read the format from
  FORMAT.md's title, which #555 retitled. FORMAT.md now carries a marker
  line, `<!-- conformance-formats: 1 2 -->`, read by the new
  `scripts/conformance-formats.sh`. The MANIFEST keeps
  `conformance_format`, one number, the newest format (now 2), and
  gains `conformance_formats=1 2`. `make lint-sync`, part of pre-push,
  fails when the marker is missing, malformed or differs from the
  reference runner's `FORMATS`, so a retitled or extended FORMAT.md
  cannot break the package unseen. The bindings read neither key.
- `karyos_message_info.extent` is documented as the facade defines it:
  the bytes the message takes in the stream, its frames and their
  alignment, ending at `position + extent`; a pad, an abort or a gap may
  follow before the next message. `abi.rs` said "to the next one", and
  `karyos.h` said nothing.

- A guarded client publication gated by the guard word before the
  close's seal landed never released, so the seal never positioned and
  its walker never wrote the `Ended` record (#526): the C ABI outcomes
  test waited for it until its bound. `ClientPublication::poll_outcomes`
  (and so `poll_outcomes_on` and `karyos_publication_poll_outcomes`) now
  releases a handle whose admission is not open once its buffer is
  sealed, resolving a forgotten claim first, as an offer does. An open
  handle's poll is unchanged. Later attempts still report `Gated`.

- Three conversions in karyos-sys saturated to `u32::MAX`, a form SPEC §14
  excludes; each is now bounded by type, with no conversion left to fail:
  - the conflation reader's queue length is a `u32`: the queue holds each
    of the table's `keys` (a `u32`) at most once, so `PollReport::pending`
    and a poll's served count come from it directly;
  - `LogBuffer::attached_subscribers` counts only the buffer's subscriber
    cells (`max_subscribers`, a `u8`), and its doc states that bound.

- A conflation table's value capacity past `u32` was saturated to
  `u32::MAX` when its shape was taken (#535), a form SPEC §14 excludes.
  `ConflationConfig::shape` now returns `Result<ConflationShape,
  ConflationError>` and refuses such a capacity with `ValueTooLarge`;
  `ConflationConfig::validate_publication` passes the refusal on, and a
  publication given such a table by `with_conflation` fails every keyed
  offer and claim with it. The shape's own check and a claim's length
  conversion refuse with `InvalidConfig` where they saturated before (a
  target whose `usize` is narrower than 32 bits).
- `karyos.h`: `karyos_publication_claim`'s doc comment held a stray `/**`
  and a repeated line, which merge `fc3be2c2` (F7a-3) left. C compilers
  warned (`-Wcomment`, "'/*' within block comment"), and so did a cgo
  build's `go vet`. `header.rs` now checks that no comment of the header
  opens another (`no_comment_of_the_header_opens_another`, with a negative
  control).

- A rejoin's outcome reported alone (`RejoinOutcome::Replayed` with no
  overrun, abort, skip or close in the same poll) reaches the facade
  caller of a `RejoiningSubscription`: the facade's poll report kept a
  summary only when it stopped (F9-0b, karyos#532).
- `karyosd --archive` admits remote `ArchiveConnection`s again. Their
  response reader is optional (#524), and an optional reader takes a
  spare-slot credit; the response stream had the default three spare
  slots, whose one free credit the daemon's own requester held, so every
  remote open was refused (`ResourcesUnavailable`). The response stream
  now has `RESPONSE_READERS` (8, as many as the request stream's
  publishers) readers and `RESPONSE_SPARE_SLOTS` spare slots, and
  `karyosd_admits_as_many_archive_connections_as_request_publishers`
  opens them all beside a boot recording. The management agent's
  catalog, which had stopped listing a karyosd Archive, lists it again
  (`the_management_agent_lists_a_karyosd_archive`; karyos-tools now has
  karyos-agent as a dev-dependency for it).
- A remote conflated grant that arrived after its request timed out was
  not released: `Connection::release` ignored `FetchableConflated`, so the
  grant stayed held until the client ended. It is now taken and dropped,
  which sends its `Detach`.

- One driver can hold both ends of a `karyos:udp` endpoint (karyos#490; D2-1 and
  D2-4). A driver's own network publication's loopback image shares the
  publication's key, and was installed but never exposed, so a subscription of
  the same driver never got an image. A network image and a local stream of the
  same key now coexist, in either order: key lookups (`AddPublication`,
  `AddSubscription`, the `karyos:ipc` URI paths, conflated views, a URI's lane
  check) take the local stream for every client, so local behaviour is
  unchanged; a network subscription attaches its images by registration
  (`AddImageSubscription`), and a key with no local stream still resolves to its
  oldest image. A replay target keeps its key to itself while it lives, retiring
  included (#283 P3). A client's `PublicationClosed` naming no image closes only
  its local links of the key and lane, never an image's. The Archive's lookups
  by (stream, session, lane) follow in karyos#490b.

- An IPC driver no longer keeps the images a connected remote subscriber
  read. A registration kept its stream from freeing, and a remote client
  had no way to remove one, so every image it took stayed Retiring, with
  its regions, descriptors and storage charge, until the client left. A
  retiring stream now frees once no lease, remote grant or lingering
  network publication holds it. An in-process registration whose
  `Remove` is still queued stays until it is served, and the `Remove`
  succeeds; a `ReportLoss` queued ahead of it is not a protocol
  violation once the stream is freed (it is counted unverified). A remote
  registration is reclaimed once its last grant ends. Stream ids and
  registration ids are never reused, so neither names a later one. A
  remote registration no longer keeps a replaced guarded incarnation by
  itself: its grants do.
  `RemoteClient::remove_subscription` removes a taken subscription, and
  the client facade releases retired, dropped and late-granted image
  handles with it (the doc-hidden `Connection::release_subscription`).
- A removed network publication's sender closes its lane queues, its repair
  queue and its route at its next duty (#354 review P3-6), on every path of a
  routed one, instead of leaving them open until the endpoint retires. A half
  the sender does not hold then, or one in another epoch, dropped them already.
  Counted (`removed_closed`); items still pending in a closing queue are
  returned and counted (`removed_returned`), and a full close list, never
  expected, is counted (`removed_unrecorded`).
- The driver's loopback tests no longer pick a free port by binding a
  socket, dropping it and binding the port again later, which another
  process could take in between. A test's embedded subscription binds on
  port 0 and its publication sends to the address the driver bound; a
  publication with no receiver sends to a socket the test holds. A test
  reads that address through `EmbeddedDriver::network_subscription_address`,
  hidden and not part of the API. Client subscriptions by URI and
  multicast groups still pick a port: a channel URI refuses port 0, and a
  group's port is named before any bind.
- A recording group's records hold only what their sources present
  (#382 review P3s): a delivery outcome takes a receiver only on a
  range-side kind and a lost count only on outcomes lost, as the outcome
  ring does; a failure's details are 0 where its variant has no field,
  and an absent `Option` is 0 in both. `record::EXTENSION` is tied to the
  frame's extension length at compile time, and the segment store's
  index header buffers use one named length.
- The segment store's arithmetic is checked (SPEC §14): five
  saturating operations in the interval sync and in recovery's counts
  are checked ones. A clock that steps back still syncs nothing.
- A guarded network publication that a guard close sealed takes its
  fresh incarnation after the reopen as a new publication identity on
  the wire, every lane at once. The first `publication()` after the
  reopen removes the old session with no linger (its closed guard sends
  no EOS) and refuses with `DriverError::QuarantinedAlias { stream,
  until_ns }`. Once the alias's `alias_quarantine` (default 10 s) has
  passed from that removal, the next call swaps in every lane and adds
  the sender again under the same alias, with incarnation N in its
  SETUP and its guard gate registered again; the send endpoints stay
  held between incarnations. Remote receivers are assumed to use the
  same `alias_quarantine`. `NetworkPublicationState::Reincarnating`
  reports the wait, and `DriverError::NetworkReincarnation` is gone. A
  network close or an agent failure before the next incarnation is
  added refuses its lanes (`NetworkUnavailable`, `NetworkAgent`) and
  leaves them sealed: they never reincarnate locally. Each incarnation
  draws its own `initial_term_id` before it is announced (SPEC §4,
  initial state), shared by its lanes; a test pin still wins.
- The network keeps one time base in every threading mode. In
  `ThreadingMode::Shared` the agents' cycles took the driver's injectable
  clock while their role clocks read `host_monotonic_ns`. On Linux every
  RTTM reply was then late (no RTT sample) and a receiver never asked
  again for a hole whose NAK or repair was lost. The network now reads
  `host_monotonic_ns` for its cycles and its close, as runner threads do;
  the driver's clock times claim deadlines only.
- A replay target checks what it is fed (#374 review). A frame whose
  header (term id and offset, from the recorded initial term id) names
  another position than where it lies in the run is refused, and a fill
  must be a PAD or ABORTED record whose extent is the one given.
  `finish_replay` and the reaping of a dropped feed refresh the stream
  gauges, and a dropped feed's target whose retire fails is counted
  (`replay targets not retired`) instead of ignored.

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
