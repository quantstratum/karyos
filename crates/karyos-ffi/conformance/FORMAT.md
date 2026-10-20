<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- conformance-formats: 1 2 -->

# Conformance scenarios, formats 1 and 2

The language-neutral conformance suite of the C ABI and the bindings
(SPEC.md §10.2, §13; ADR-0053, ADR-0067) lives here, beside
`karyos-ffi`. ADR-0073 settles its format (owner item 46, decision
BIND-Q2): format 1 tests the C ABI through its functions and is kept;
format 2 adds a semantic layer of ops that every binding runs through
its public API, full 64-bit values, the steps that require a scenario,
the features it needs, and the identities a run pins. A binding's
runner can be written from this file alone, with its language's
standard library; the Rust runner, `../tests/conformance.rs`, is the
reference, and its semantic adapter (`../tests/support/semantic.rs`)
runs the ops as a minimal binding over the C ABI.

## Files

- This file's second line, `<!-- conformance-formats: 1 2 -->`, lists
  the formats the suite holds, ascending. Tools read it, not the title:
  `scripts/conformance-formats.sh` prints it, the libkaryos package
  records it in its MANIFEST, and `make lint-sync` fails when it differs
  from the reference runner's formats.
- `scenarios/*.kcs`: one scenario per file, UTF-8, read line by line. A
  file in `scenarios/` with another extension is a failure.
- `index.txt`: the coverage map from the §13 contract rows to scenario
  ids (Index, below).
- The status names come from `../include/karyos.h` (`#define KARYOS_OK`,
  `#define KARYOS_E_*`); a runner reads them from the header of the
  library it tests, never from a copy.

## Lines and tokens

Outside a quoted string, `#` starts a comment that runs to the end of
the line. A line that holds only whitespace or a comment is blank and is
ignored everywhere, before `format` too. Every other line is a keyword
followed by tokens.

Tokens are separated by runs of whitespace: spaces and tabs. A token is
a run of characters with no whitespace between them, in which a double
quote opens a quoted string that runs to the next unescaped double
quote. Inside a quoted string, whitespace and `#` are literal, and `\"`
and `\\` are the only escapes; any other backslash, or a line that ends
inside a string, is a failure. So `text="a # b"` is one token, the name
`text`, `=`, and the quoted value.

| Keyword | Tokens | Meaning |
| --- | --- | --- |
| `format` | `1` or `2` | The format version; the first line that is not blank |
| `id` | a name without whitespace | The scenario's id, unique in the suite |
| `abi` | `MAJOR.MINOR` | The ABI version the scenario needs |
| `covers` | one quoted string | The §13 contract row it checks, as `index.txt` names it |
| `call` | a function name, then `name=value` arguments | Calls the C function |
| `expect` | an optional status name, then `name=value` results | Checks the last call |
| `since` | a step | Format 2 only, and required there (Format 2) |
| `feature` | a feature name | Format 2 only; repeatable (Format 2) |
| `op` | an op name, then `name=value` arguments | Format 2 only: runs the op (Format 2) |

`format`, `id`, `abi`, `covers` and `since` come once each, and
`feature` once per feature, in any order after `format` and all before
the first step. A step is a `call` or an `op`; every step is followed by
exactly one `expect`, before the next step. A scenario has at least one
step. A `name=value` token splits at its first `=`, and a name given
twice in one line is a failure.

## Values

- An integer: decimal, optionally negative. In format 1 it lies within
  64-bit signed range (`108`, `-1`); in format 2 from -2^63 to 2^64 - 1,
  so a `uint64_t` handle or position past the signed range can be
  written (`18446744073709551615`). An argument whose type is narrower
  (such as the `int32_t` `status`) and that does not fit it is a
  failure.
- `null`: a null pointer, for a pointer argument.
- A quoted string.
- `$name`: a variable. Variables live for one scenario and carry across
  its steps. In an `expect`, an unbound variable binds to the result,
  and a bound one is compared with it. In a `call`, a variable must be
  bound by an earlier `expect` of the same scenario.

## Calls

A runner passes every pointer argument a scenario does not name as a
valid pointer to a value it owns, and reads the results from there. A
scenario names an argument only to pass something else, such as `null`.
The arguments and results of each function are those of the header:

| Function | Arguments | Results |
| --- | --- | --- |
| `karyos_abi_version` | `major`, `minor`, `patch` (`null` only) | status, `major`, `minor`, `patch` |
| `karyos_status_message` | `status` (required) | `text` (no status) |
| `karyos_driver_create` | `size`, `reserved`: the options of `karyos_driver_options_init`, with `reserved` set when given | status, `driver` |
| `karyos_driver_start` | `driver` (required), `idle_strategy` (default `KARYOS_IDLE_YIELD_THEN_SLEEP`, 3, the ABI's declared default), `idle_sleep_ns` (default 0) | status |
| `karyos_driver_stop` | `driver` (required) | status |
| `karyos_driver_add_stream` | `driver` and `stream_id` (required), `allow_unconnected`, `schedule_capacity`, `conflation_keys`, `conflation_value_capacity`, `conflation_journal_capacity`, `publication_mode`, `publishers`, `size`: the options of `karyos_stream_options_init` otherwise | status |
| `karyos_driver_subscribe_conflated` | `driver` and `stream_id` (required) | status, `conflated` (on `KARYOS_OK`) |
| `karyos_conflated_poll` | `conflated` (required), `key_budget` (default 1): a handler that counts the values | status, `delivered` (the count written, checked against the handler's calls) |
| `karyos_conflated_close` | `conflated` (required) | status |
| `karyos_client_add_conflated_subscription` | `client` and `stream_id` (required), `uri` (default `"karyos:ipc"`) | status, `conflated` (on `KARYOS_OK`) |
| `karyos_driver_connect` | `driver` (required) | status, `client` |
| `karyos_driver_do_work` | `driver` (required) | status, `work` |
| `karyos_driver_close` | `driver` (required) | status |
| `karyos_client_poll` | `client` (required) | status, `served` |
| `karyos_client_close` | `client` (required) | status |
| `karyos_client_connect` | `size` (required): the options of `karyos_client_options_init` with a null `dir` | status |
| `karyos_client_add_publication` | `client` and `stream_id` (required), `uri` (default `"karyos:ipc"`), `detail_size` | status, `publication` (on `KARYOS_OK`), `detail_written`, `code`, `value`, `detail_tail` |
| `karyos_client_add_concurrent_publication` | `client` and `stream_id` (required), `uri` (default `"karyos:ipc"`), `detail_size` | status, `publication` (on `KARYOS_OK`), `detail_written`, `code`, `value`, `detail_tail` |
| `karyos_publication_offer` | `publication` (required), `lane` (default 0), `payload` or `length` (one of them), `accepted_size` | status, `lane`, `position`, `tail` |
| `karyos_publication_offer_at` | `publication` and `tx_time` (required), `lane` (default 0), `payload` or `length` (one of them), `accepted_size` | status, `lane`, `position`, `tail` |
| `karyos_clock_now` | `domain` (required): `KARYOS_CLOCK_MONOTONIC` 0 or `KARYOS_CLOCK_TAI` 1 | status, `now` (when written) |
| `karyos_publication_claim` | `publication` and `length` (required), `lane` (default 0) | status, `claim` (on `KARYOS_OK`) |
| `karyos_claim_commit` | `claim` (required), `accepted_size` | status, `lane`, `position`, `tail` |
| `karyos_claim_abort` | `claim` (required) | status |
| `karyos_publication_close` | `publication` (required) | status |
| `karyos_client_add_subscription_with` | `client` and `stream_id` (required), `uri` (default `"karyos:ipc"`), `size`, `role`, `rejoin`, `reserved`: the options of `karyos_subscription_options_init` with each given field set | status, `subscription` (on `KARYOS_OK`) |
| `karyos_subscription_close` | `subscription` (required) | status |
| `karyos_publication_offer_with` | `publication` (required), `lane` (default 0), `payload` or `length` (one of them), `size`, `reserved`, `reserved_value`: the options of `karyos_offer_options_init` with each given field set, `accepted_size` | status, `lane`, `position`, `tail` |
| `karyos_subscription_poll` | `subscription` (required), `limit` (default 1), `handler`: `"keep"` (default) keeps each message's bytes; `"reenter"` also polls the same subscription from inside the handler, once, with a limit of 1 | status, `delivered` (the count written, checked against the handler's calls), `last` (the last message delivered, as UTF-8 text, when there is one), `reentered` (with `"reenter"`, the name of the status the inner poll returned, as text) |
| `karyos_publication_poll_outcomes` | `publication` (required), `lane` (default 0), `limit` (default 1): a handler that counts the records | status, `delivered` (the count written, checked against the handler's calls) |

`payload` is a quoted string whose UTF-8 bytes are the message; `length`
is a message of that many zero bytes. A `karyos_client_connect` with a
size the library accepts goes on to find no driver, and what it answers
then depends on the platform: a scenario names only a size below the
smallest.

A handle is an integer value, bound from a result (`expect KARYOS_OK
driver=$driver`) and passed back (`call karyos_driver_do_work
driver=$driver`).

A result named in an `expect` that the call did not write is a failure.

## Sized structs

A struct whose first field is its `uint32_t` size (SPEC.md §10.2) is
passed as a header of another minor version lays it out, so a scenario
can check both halves of minor compatibility. An argument `size`,
`detail_size` or `accepted_size` sets the size field to its value; left
out, it is the size of the struct in the header the runner reads.

- The runner places the struct in 8-aligned memory of the larger of that
  size and its header's size, plus 16 bytes, and fills every byte the
  struct does not set with the sentinel `0xA5`: the tail past its
  header's size, and every field but the size of an output struct
  (`karyos_detail`, `karyos_accepted`).
- An input struct carries the values the defaults or the other arguments
  give it, then the sentinel.
- An output field is written when it no longer holds the sentinel; only
  then is it a result (`lane` and `position` of `karyos_accepted`;
  `code` and `value` of `karyos_detail`). `detail_written` is 1 when
  `code` and `value` were written, 0 otherwise, so a scenario can expect
  nothing written. A field written with a value whose bytes are all
  `0xA5` reads as unwritten: no 0.1.0 output field holds such a value in
  practice, but a runner cannot tell it apart.
- `tail` (`karyos_accepted`) and `detail_tail` (`karyos_detail`) are
  `"intact"` when every byte past the header's size still holds the
  sentinel, `"changed"` otherwise.

## Format 2

A format 2 scenario uses the lines, tokens and values above, with the
additions of this section. Format 1 scenarios run unchanged.

### Layers

A format 2 scenario's steps are all `call`, or all `op`; mixing them is
a failure.

- **The ABI layer** (`call`): the functions, arguments and results of
  Calls and Sized structs, with format 2 values. The runners that drive
  the C ABI run it.
- **The semantic layer** (`op`): ops that a binding runs through its
  public API, with no private shortcut, and the outcomes and close rules
  below. Its expectations are those of a binding, which need not equal
  the raw C answers: a second close is `ok` where the C ABI answers
  `KARYOS_E_CLOSED`. Every runner runs it, the reference runner through
  its adapter.

### Steps

`since` names the delivery step from which a scenario is required:
`B0` to `B5`, as each binding SPEC numbers its steps in its steps table
(quantstratum-docs: `karyos/design/bindings-plan.md` §2). It names a
binding SPEC's step, never a batch of that plan's §7, whose numbers
differ. A runner declares the step it targets. Where the binding SPECs
place one surface at different steps, a scenario carries a `feature`
for it rather than a `since` that one binding would get wrong.

### Features

A scenario names with `feature` each feature its ops need; an op used
without its feature is a failure. A runner declares the features it
offers. The features are:

| Feature | What it needs |
| --- | --- |
| `archive-replay` | An Archive the runner provides, and the replay ops: `archive.*`, `replay.subscribe` (Archive replays, below; Linux only) |
| `claim-retry` | A claim held across calls: `publication.claim`, `claim.commit`, `claim.abort` (the C++ and Go object APIs) |
| `concurrent-publication` | `publication.add_concurrent` |
| `conflation` | The conflated views: `driver.subscribe_conflated`, `conflated.*` |
| `embedded-driver` | A driver the scenario creates: `driver.*` |
| `guarded-publication` | The outcome stream: `publication.poll_outcomes` |
| `tai-clock` | `clock.now` of the TAI domain, which some platforms lack |

A new feature is added here; a feature name not in this table is a
failure.

### The provided driver

A semantic scenario without `embedded-driver` creates no driver. Before
its first step the runner binds `$driver` to a driver it provides,
started and serving streams 1 to 15 with the default stream options:
an embedded driver of its own, or a driver it starts or attaches to
where the binding has no embedded one. The reference runner provides
an embedded driver, closed after the scenario.

### Outcomes

An `op` is followed by an `expect` that starts with its outcome:

- `ok`, then the results it checks as `name=value`;
- `status=<name>`: a failure, named by its header status in lower case
  without `KARYOS_E_` (`not_connected`, `claim_outstanding`, `closed`),
  with no results but one exception below. A binding maps its own
  results to these names through the one mapping it already has
  (BIND-S1); the class follows the header's range, and whether the
  binding returns or raises it is the binding's own policy. A name the
  header does not define is a failure, and so is `invalid_handle`,
  which no op answers (Close). The exception: after `status=refused`,
  `archive.replay` and `archive.stop_replay` may check `code=<n>`, the
  Archive's response code (1 an error, such as a host's refusal; 2 an
  unknown recording; 3 an unknown replay; 4 an invalid request; 5 an
  unsupported schema), so a refusal for one reason cannot pass for
  another.

A result checked as `name>=value` (format 2, either layer) holds an
integer at least `value`; `value` is a literal or a bound variable.

Objects (the arguments named `archive`, `driver`, `client`,
`publication`, `subscription`, `conflated` and `claim`) are opaque: an
op's result binds one to a variable, and an op takes it only as a
variable. A result an op does not have, or an argument it does not
take, is a failure; so is a required argument left out.

### Close

- A close after the object's successful close is `ok` and closes
  nothing more.
- Closing a parent closes its children: a driver its clients and views,
  a client its publications, subscriptions and views, a publication its
  claim. A child's close after its parent's close is `ok`, as a
  deferred close or a destructor runs it. This covers the closes of the
  table below, not `claim.abort`, which is no close (the last rule).
- Any other op on a closed object, or on a child of a closed parent,
  answers `status=closed`, whatever the C ABI answers for its stale
  handle.
- A close that answers `busy` or `reentrant` closes nothing: the object
  stays usable and the close may be retried.
- A claim ends at a successful commit, at an abort, at a commit that
  answers a status other than the five retryable ones
  (`back_pressured`, `not_connected`, `admin_action`, `rate_limited`,
  `gated`), which keep it staged, or at the close of its publication or
  client. An ended claim answers `closed` to both `claim.commit` and
  `claim.abort`.

### Ops

Arguments in brackets are optional; `payload` or `length`, one of them,
gives a message as in Calls. `->` lists the results of `ok`.

| Op | Arguments | Results | Feature |
| --- | --- | --- | --- |
| `library.version` | none | `major`, `minor`, `patch` | |
| `clock.now` | `domain`: `"monotonic"` or `"tai"` | `now` | `tai-clock` for `"tai"` |
| `driver.create` | none | `driver` | `embedded-driver` |
| `driver.add_stream` | `driver`, `stream_id`, [`allow_unconnected`, `publication_mode`, `publishers`, `spare_slots`, `term_length`, `conflation_keys`, `conflation_value_capacity`, `conflation_journal_capacity`]: the stream options otherwise | none | `embedded-driver` |
| `driver.start` | `driver`, [`idle_strategy`: `"busy_spin"`, `"yield"`, `"sleep"` or `"yield_then_sleep"`, default `"yield_then_sleep"`, the ABI's declared default; `idle_sleep_ns`] | none | `embedded-driver` |
| `driver.do_work` | `driver` | `work` | `embedded-driver` |
| `driver.subscribe_conflated` | `driver`, `stream_id` | `conflated` | `embedded-driver`, `conflation` |
| `driver.close` | `driver` | none | `embedded-driver` |
| `client.connect` | `driver` | `client` | |
| `client.poll` | `client` | `served` | |
| `client.close` | `client` | none | |
| `publication.add` | `client`, `stream_id`, [`uri`, default `"karyos:ipc"`] | `publication` | |
| `publication.add_concurrent` | as `publication.add` | `publication` | `concurrent-publication` |
| `publication.offer` | `publication`, [`lane`], `payload` or `length` | `lane`, `position` | |
| `publication.publish_claimed` | `publication`, [`lane`], `payload` or `length` | `lane`, `position` | |
| `publication.claim` | `publication`, `length`, [`lane`] | `claim` | `claim-retry` |
| `claim.commit` | `claim` | `lane`, `position` | `claim-retry` |
| `claim.abort` | `claim` | none | `claim-retry` |
| `publication.poll_outcomes` | `publication`, [`lane`, `limit` (default 1)] | `delivered` | `guarded-publication` |
| `publication.close` | `publication` | none | |
| `subscription.add` | `client`, `stream_id`, [`uri`, `role`, `rejoin`: the values of the header's subscription options] | `subscription` | |
| `subscription.poll` | `subscription`, [`limit` (default 1)] | `delivered`, `last` (the last message as UTF-8 text, when there is one) | |
| `subscription.close` | `subscription` | none | |
| `conflated.add` | `client`, `stream_id`, [`uri`] | `conflated` | `conflation` |
| `conflated.poll` | `conflated`, [`key_budget` (default 1)] | `delivered` | `conflation` |
| `conflated.close` | `conflated` | none | `conflation` |
| `subscription.poll_to_end` | `subscription`, [`limit` (default 16)] | `delivered` (the count of every poll), `last` | |
| `subscription.end` | `subscription` | `reason`: `"none"`, `"end_of_stream"`, `"image_retired"`, `"stream_removed"`, `"revoked"`, `"closed_by_overrun"` or `"other"`; `position`; `seal_code` | |
| `archive.connect` | `client` | `archive` | `archive-replay` |
| `archive.replay` | `archive`, `recording`, `target_stream_id`, [`position` (default 0), `length` (default to the recording's end), `rate`: `"full"` (default), `"as_recorded"` or `"scaled"`, `scale_ppm`] | `replay`, `session` | `archive-replay` |
| `archive.stop_replay` | `archive`, `replay` | none | `archive-replay` |
| `archive.close` | `archive` | none | `archive-replay` |
| `replay.subscribe` | `client`, `stream_id`, `session` | `subscription` | `archive-replay` |

A text argument with a fixed set of values (`domain`, `idle_strategy`)
is checked when the scenario is read, so a value outside its set fails
even in a scenario reported `skipped`, `later` or `unsupported`; so
does `clock.now` with `domain="tai"` in a scenario without `feature
tai-clock`.

`subscription.poll_to_end` polls the subscription, serving its client
before each poll, until a poll answers `closed` or `closed_by_overrun`,
then answers `ok` with the messages delivered on the way and the last
of them; another status ends it with that status, and no end within 20
s (past a replay target's linger, 5 s) answers `timeout`.
`subscription.end` reads how a stream subscription ended
(`karyos_subscription_end_state`): `"none"` while it has not, and for a
network subscription, whose images' ends its image changes report.
`seal_code` is the raw seal code of the core, which a scenario does not
pin; `reason` and `position` are the contract.

`publication.publish_claimed` is one claim, fill and commit through the
binding's claim API (BIND-S3): on a retryable status it returns that
status with no claim left outstanding, so the next attempt starts
afresh. An object API runs it as a claim, a commit and, on a retryable
status, an abort; a fill-callback API as its one commit attempt. Every
binding offers it, so it needs no feature.

### Archive replays

Feature `archive-replay` (B6; quantstratum-docs:
`karyos/design/archive-replay-control.md`). It needs a client of a
driver that runs an Archive, which a runner provides as below, with no
Rust: Linux only, because the client attaches to a driver in another
process, which only Linux's remote client does. A runner elsewhere
declares the feature absent.

- **karyosd.** The runner starts the karyosd of the pinned core:
  `KARYOS_KARYOSD` when set, else `bin/karyosd` of the conformance test
  kit (`make libkaryos-testkit`, beside the libkaryos package and from
  the same core commit, which its MANIFEST records), else one built with
  `cargo build --release --locked -p karyos-tools --bin karyosd` from
  the pinned core. The core's own runner builds it in the test's
  profile instead, beside the test binary:

  ```text
  karyosd --dir <private directory> --stream 20:1 --archive <empty directory>
          --archive-control 1030,1031 --record 20:1
  ```

  Stream 20 is recorded from boot; 1030 and 1031 are the Archive's
  request and response streams. Stream 1041, the replay target's, is
  not configured: each replay opens its own target there. Its output
  goes to a file the runner prints when the provisioning or a scenario
  fails; after the scenarios the runner sends it SIGTERM, waits at most
  10 s, then sends SIGKILL.
- **Seeding.** The runner connects a client with
  `karyos_client_connect` to that directory, binds it to
  `$archive_client`, and through it publishes the messages `"r0"` to
  `"r9"` on `karyos:ipc` stream 20, with a pause of 5 ms between `"r4"`
  and `"r5"` (so a replay at a millionth of the recorded pace holds the
  second half). It then opens an Archive connection (client id 1, the
  streams above, a deadline of 10 s) and lists the catalog until the
  first recording's position is past the last message's start, which,
  one frame, is then recorded whole; it binds `$recording` to that
  recording's id and `$recording_end` to that position, and closes the
  connection. The recording stays live: karyosd cannot stop it from C
  (recording control is B6b), so scenarios replay an explicit length.
- **Connections.** `archive.connect` opens a connection on the streams
  above with a deadline of 10 s and a client id the runner hands out,
  100, 200 and up, so no connection's id, nor its replayer's (one
  more), meets another's, and a late answer never lands in another
  connection. The request stream takes 8 concurrent publishers (karyosd's
  `REQUEST_PUBLISHERS`): the provisioning holds none once seeded, and a
  scenario at most two, its connection and that connection's replayer.
- **Replay subscriptions.** `replay.subscribe` serves the client until
  the target's grant (`KARYOS_E_NOT_CONNECTED` before it), up to the
  connection's deadline, then answers `timeout`: no grant by then, not
  a transport failure.
- **Isolation.** A scenario uses `$archive_client` and never closes it:
  its close ends only the scenario's use of it. At a scenario's end the
  runner stops every replay the scenario started and did not stop
  (their answers ignored), since closing a connection leaves its
  replays running, then closes what the scenario left open.

### Bounds

A runner refuses, as a failure, a scenario file over 64 KiB, a line
over 4096 bytes or 64 tokens, a scenario over 1024 steps or 256
variables, and a suite over 4096 scenarios. Integers are bounded as in
Values; a runner holds them in a type that carries the whole range.

### Pinning

A run prints, before any outcome, the identities it ran with:

```text
suite <sha256> header <sha256> core <major.minor.patch> <library id>
```

- `suite`: SHA-256 over the suite's files, `FORMAT.md`, `index.txt`
  and every file under `scenarios/` (only `.kcs` files may be there,
  Files), sorted by their path under this directory as
  bytes, each hashed as its path in UTF-8, a NUL byte, its length as
  8 bytes big-endian, then its bytes.
- `header`: SHA-256 of the `karyos.h` the runner was compiled against,
  not one installed beside the library.
- `core`: the library's `karyos_abi_version`, then its identity: the
  SHA-256 of the `libkaryos` file the runner links, or for the
  reference runner `karyos-ffi` and the crate's version.

The Python binding wraps the Rust crates, not the C ABI: it prints the
suite, then its semantic target in place of the header and core,
`core <release> protocol <version>`, the core release and the protocol
version it was built against.

## Failures

A scenario fails, and is reported as failed, on any of these:

- an unknown `format`, keyword, function, op, argument, result, step,
  feature or status name (a status name the header does not define). A
  runner that meets a function, op or argument it does not know fails
  the scenario, never skips it, so an older runner never passes a newer
  scenario by ignoring part of it;
- a header line repeated, missing, or after a step; `since` missing in
  format 2; `since`, `feature`, `op` or `>=` in format 1;
- a step without its `expect`, an `expect` without a step, no step at
  all, or `call` and `op` in one scenario;
- an op used without the feature it needs, or an object argument not
  passed as a variable;
- a breach of the bounds (Format 2, Bounds);
- a malformed token or value (Lines and tokens, Values);
- an unbound variable in a `call`;
- a status that differs from the `expect`'s, an `expect` with a status
  for a function that returns none, or one without a status for a
  function that returns one;
- a result that differs from the `expect`'s, or was not written.

## Versions

The ABI version is independent of the workspace version. A runner calls
`karyos_abi_version` first, before any other call. This suite needs ABI
0.1.0 or a later 0.1.z: before 1.0 a runner accepts exactly the 0.y the
suite targets, with at least its minimum 0.y.z, and checks it once,
before any scenario; a library outside it fails the run.

A runner then compares each scenario's `abi` with the library's. A
scenario runs when the major versions are equal and:

- before 1.0 (major 0), the minor versions are equal, because a `0.y`
  minor may break (ffi-gap-analysis.md §4.5);
- from 1.0 on, the scenario's minor is not newer than the library's,
  because minors only add.

Any other scenario is skipped, never reported as passed.

## Reporting

A runner prints the pinning line first (Format 2, Pinning), then the
step it targets and its declared features,

```text
step <step> offers <feature ...|none> absent <feature ...|none>
```

in which every feature of Format 2, Features appears once, offered or
absent, then every scenario id with one outcome, and for a failure the
file and line of the step that failed:

- `passed`;
- `failed`;
- `skipped`: its `abi` does not run against the library (Versions);
- `unsupported <feature>`: it needs a feature the runner declared
  absent. A feature the runner neither offers nor declares absent is a
  failure, never `unsupported`;
- `later`: its `since` step comes after the runner's step.

A runner checks a scenario in that order, its `abi` (`skipped`), its
`since` (`later`), then its features (`unsupported`), and reports the
first that applies, so the reports of two runners compare line by line.

A scenario is required when its `abi` runs, its `since` is the runner's
step or earlier, and the runner offers its features; a required
scenario passes or fails, and is never skipped. A binding release
requires no failure, no skip at the ABI version it targets and no
`later` at the step it releases (SPEC.md §13). Each `unsupported` is
one of the features its binding SPEC lets it lack at that step, and the
binding's runner states which features it offers and why it lacks the
others. The declaration line lets a release gate check the absent
features against the binding SPEC from the run's output alone. The
coverage map of a run is its rows with each scenario's outcome, so
applicable, missing and unsupported features are told apart
(ADR-0073, Coverage).

## Index

`index.txt` holds one row per line, with `#` comments and blank lines as
in scenarios:

```text
<row name>: <scenario id> [<scenario id> ...]
<row name>: pending <batch or reason>
```

The row name is the text before the first `:`, trimmed, not empty and
without `#`; rows are unique. After the `:` comes either one or more
scenario ids separated by whitespace, or `pending` followed by the
batch of ffi-gap-analysis.md (or the reason) that will cover the row.
A row lists scenarios of either format and layer.

Scenario ids are stable: a scenario keeps its id when it changes, and
an id once used is never given to another scenario.

The map is checked both ways, and any breach is a failure:

- every id a row lists names an existing scenario whose `covers` is that
  row;
- every scenario is listed by the row its `covers` names, so a scenario
  appears under exactly one row.
