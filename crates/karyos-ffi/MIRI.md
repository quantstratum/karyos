<!-- SPDX-License-Identifier: Apache-2.0 -->

# What Miri covers in karyos-ffi

`make miri` runs this crate's tests under Miri. The project owner's
merge condition for a PR that touches `src/abi.rs` (owner item 45) is
Miri per this file on the PR's head, with its output. An ADR-0034 review
record cites this file for what Miri does and does not cover.

## The profile

Most of the crate's tests drive an embedded driver on a thread of its
own. Under Miri each spin of a waiting thread is interpreted, so a test
whose threads yield in a loop costs hours. The profile keeps the
coverage of every unsafe site and drops that cost:

- **Waits sleep under Miri.** The test driver's thread sleeps a
  millisecond after a duty cycle with no work, and the tests' clients
  and loops do the same (`idle` and `test_context` in
  `src/abi/tests.rs`). Miri does not interpret a sleeping thread, so the
  thread with work runs. Natively they still yield.
- **One boundary test per unsafe site class.** Every class of unsafe
  operation in `src/abi.rs` has at least one test that runs under Miri
  (the table below).
- **Driver integration is native only.** A test that adds nothing to
  the unsafe coverage, only more driver behaviour, carries
  `#[cfg_attr(miri, ignore = "driver integration; covered natively")]`
  and runs on macOS and Linux.
- **Budget.** The tests of a full `cargo +nightly miri test -p
  karyos-ffi` run within 30 minutes once Miri's build is warm. A cold
  build compiles the whole dependency tree under Miri first, which takes
  longer than the tests and is not counted. A PR states both times, and
  the machine's load, and explains a test time over the budget.

A PR that adds an unsafe site adds its row here and a test that runs
under Miri, or states why none can.

## Unsafe sites and their Miri tests

`src/abi.rs` holds the crate's unsafe code (`lib.rs` expects it only on
`mod abi`; `make lint-sync` checks it). `tests/support/abi.rs` holds the
test-only unsafe of the integration tests.

| Unsafe site class | Functions | Miri test |
| --- | --- | --- |
| Out-parameter writes, after the null and alignment check | every export with a pointer result | `abi::tests::connect_refuses_bad_arguments_and_writes_nothing`, `tests/abi.rs` `a_null_or_misaligned_out_parameter_is_refused_with_nothing_written`, and each test below |
| Version writes | `karyos_abi_version` | `tests/abi.rs` `the_abi_version_is_0_1_0` |
| Static status text | `karyos_status_message` | `tests/abi.rs` `every_status_has_static_text` |
| Sized struct reads by prefix (`size` read first) | `karyos_client_connect` | `abi::tests::connect_reads_the_options_to_their_last_field`, `a_struct_from_a_newer_header_is_read_and_written_by_its_prefix` |
| Sized struct writes by prefix (`write_sized`) | `write_detail`, `write_accepted`, the image change | `abi::tests::a_struct_from_a_newer_header_is_read_and_written_by_its_prefix`, `a_publication_offers_and_commits_staged_claims` |
| C strings (`read_str`, the options' `dir`) | `karyos_client_connect`, the add calls | `abi::tests::add_publication_refuses_bad_arguments`, `an_invalid_context_is_refused_with_its_detail_cleared` |
| The offer's payload slice (`from_raw_parts`, null with length 0) | `karyos_publication_offer` | `abi::tests::a_publication_offers_and_commits_staged_claims` |
| The claim's staged buffer: the caller writes through `*mut u8`, the commit loads it | `karyos_publication_claim`, `karyos_claim_commit` | `abi::tests::a_publication_offers_and_commits_staged_claims` (a concurrent handle's claim takes the same path; `concurrent_handles_share_a_stream_on_lane_0` is native only) |
| The handler call: a private copy and a local info, valid for the call | `karyos_subscription_poll` | `abi::tests::a_subscription_delivers_each_message_from_its_private_copy` |
| Reentrancy from the handler | `karyos_subscription_poll` and the closes | `abi::tests::a_handler_that_reenters_its_subscription_is_refused` |
| A panic inside a call: poison, never an unwind across the ABI | `guard`, every export | `boundary::tests::a_panic_in_the_body_returns_internal`, `abi::tests::a_panic_in_the_poll_poisons_the_subscription`, the `handles::` poison tests |
| The image change's `size` read before the handle | `karyos_subscription_next_image_change` | `abi::tests::next_image_change_checks_its_struct_before_its_handle` |
| `has` and `lost` writes | `karyos_subscription_next_image_change`, `karyos_subscription_image_changes_lost` | `abi::tests::a_subscription_delivers_each_message_from_its_private_copy` |
| The served flag | `karyos_client_poll` | `abi::tests::a_client_handle_is_served_and_closed_once` |
| Driver and stream options read by prefix (`read_sized`; integer-only structs) (F5) | `karyos_driver_create`, `karyos_driver_add_stream` | `abi::tests::a_driver_options_struct_is_read_to_its_last_field`, `a_stream_options_struct_is_read_to_its_last_field`, `an_older_structs_missing_tail_keeps_the_defaults` |
| Client options: the init write of the defaults, including `KARYOS_IDLE_YIELD_THEN_SLEEP` (ADR-0066), and an unknown strategy refused before any use | `karyos_client_options_init`, `karyos_client_connect` | `abi::tests::options_init_fills_the_defaults_and_the_size`, `connect_refuses_bad_arguments_and_writes_nothing`; the mapping to the facade, `api::client::tests::each_idle_strategy_maps_to_the_facades`, has no unsafe; the driver thread's strategy (`karyos_driver_start`) is driver integration, native only |
| Options init writes (F5) | `karyos_driver_options_init`, `karyos_stream_options_init` | `tests/driver.rs` `the_options_carry_their_size_and_the_drivers_defaults`, `a_stream_is_added_and_removed_through_the_abi` |
| Driver out-parameters and detail (F5) | `karyos_driver_create`, `_do_work`, `_connect`, `_add_stream` | `tests/driver.rs` `a_struct_below_the_first_size_is_refused`, `a_refused_configuration_fills_nothing_but_the_status`, `a_client_of_the_driver_is_served_and_follows_its_close`, `a_stream_is_added_and_removed_through_the_abi` |
| The outcome handler call: a local `karyos_outcome`, valid for the call; reentry refused (F7a-2) | `karyos_publication_poll_outcomes` | `abi::tests::outcomes::records_reach_the_handler_which_cannot_reenter_its_publication` |
| The outcome poll's arguments and `delivered` write, checked before the handle (F7a-2) | `karyos_publication_poll_outcomes` | `abi::tests::outcomes::the_arguments_are_checked_before_the_handle` |
| The timed offer's payload slice (F7a-3) | `karyos_publication_offer_at` | `abi::tests::a_timed_offer_checks_its_arguments_first` |
| The clock's `now` write; nothing written on refusal (F7a-3) | `karyos_clock_now` | `abi::tests::the_clock_reads_the_monotonic_domain_and_refuses_bad_arguments` (a TAI read is native only) |
| Subscription options: the init write, the prefix read, a newer struct by prefix (F7b-1) | `karyos_subscription_options_init`, `karyos_client_add_subscription_with` | `abi::tests::subscription_options_init_fills_the_defaults_and_the_size`, `add_with_refuses_bad_options_and_opens_nothing`, `an_optional_reader_under_close_is_closed_by_its_overrun` |
| Offer options: the init write, the prefix read, the payload slice (F7b-2a) | `karyos_offer_options_init`, `karyos_publication_offer_with` | `abi::tests::offer_options_init_fills_the_defaults_and_the_size`, `offer_with_refuses_bad_options`, `an_offer_carries_its_reserved_value` |
| Stream options of three layouts (64, 80, 88), refused between them and with a nonzero `reserved` (F7b-2b; concurrent streams) | `karyos_driver_add_stream` | `abi::tests::conflated::stream_options_take_three_layouts_and_nothing_between` |
| Conflated views: the out-parameters, the arguments checked before the handle (F7b-2b, F7b-2c) | `karyos_driver_subscribe_conflated`, `karyos_client_add_conflated_subscription`, `karyos_conflated_poll` | `abi::tests::conflated::conflated_calls_check_their_arguments`, `a_client_view_checks_its_arguments` |
| The conflated handler call: the reader's private copy of a value, valid for the call; `delivered` (F7b-2b) | `karyos_conflated_poll` | `abi::tests::conflated::a_conflated_view_delivers_each_keys_latest_value` |
| Archive options read by prefix; the `archive` out-parameter (F9a) | `karyos_archive_connect` | `abi::tests::archive::a_connect_refuses_bad_options_before_its_client`, `a_connect_refuses_a_client_id_past_32_bits` |
| The recording handler call: a local `karyos_recording` and its channel pointer, valid for the call; `delivered`, `detail`; reentry refused (F9a) | `karyos_archive_list` | `abi::tests::archive::a_listing_pages_through_the_catalog_after_an_id`, `a_listing_asks_nothing_for_no_limit_or_past_the_last_id`, `an_archive_refusal_carries_its_response_code`, `a_page_that_does_not_arrive_in_time_delivers_nothing`, `a_listing_refuses_a_null_handler_and_misaligned_count`, `a_handler_cannot_reenter_its_archive` (in-memory transports, no driver) |
| Subscription options of two layouts (16 and 40 bytes), refused between them; the Archive rejoin's fields read by prefix (F9b) | `karyos_subscription_options_init`, `karyos_client_add_subscription_with` | `abi::tests::subscription_options_init_fills_the_defaults_and_the_size`, `add_with_refuses_bad_options_and_opens_nothing` (a rejoin with a driver is native only: `abi::tests::rejoin::a_rejoining_subscription_reads_live_and_reports_its_state`) |
| The rejoin state: `size` read first, nothing written on refusal, the sized write by the caller's size (F9b) | `karyos_subscription_rejoin_state` (`write_rejoin_state`) | `abi::tests::rejoin::the_rejoin_state_is_written_by_the_callers_size` (no driver) |
| Replay options: the init write, the prefix read, the target channel's C string read during the call (F9c) | `karyos_replay_options_init`, `karyos_archive_replay` | `abi::tests::replay::the_replay_options_are_initialized_and_checked`, `a_replay_checks_its_arguments_before_its_handle`, `a_replay_is_started_and_stopped_driverless` (in-memory transports, no driver) |
| A replay's `replay_id` and `session_id` out-parameters and its `detail` (F9c) | `karyos_archive_replay`, `karyos_archive_stop_replay` | `abi::tests::replay::a_replay_is_started_and_stopped_driverless`, `a_refused_or_unanswered_replay_reports_why` (no driver) |
| Replay subscription options: the init write, the prefix read of a non-null struct, checked before the client (F9c) | `karyos_replay_subscription_options_init`, `karyos_client_add_replay_subscription` | `abi::tests::replay::the_replay_options_are_initialized_and_checked` (the granted subscription's out-parameter, the class of every add, is native only: `a_replay_through_a_real_archive_ends_at_its_targets_seal`) |
| The image change's end fields, written by the caller's size: a 24-byte struct takes none, a 48-byte one takes them, a newer one keeps its tail | `karyos_subscription_next_image_change` (`write_image_change`) | `abi::tests::an_image_change_is_written_by_the_callers_size` (no driver) |
| The subscription end: `size` read first, nothing written on refusal, the sized write by the caller's size (F9c) | `karyos_subscription_end_state` (`write_subscription_end`) | `abi::tests::replay::the_subscription_end_is_written_by_the_callers_size` (no driver) |
| The sized inits (owner item 48's option A, interim): `init_sized` writes `min(size, ours)` bytes and the size; the legacy `karyos_*_init` symbols write only the 0.1.0 size; a growing struct needs only its `uint32_t` size aligned (`sized_struct`, for `init_sized`, `write_sized` and `read_sized`) | the seven `karyos_*_options_init` and `_init_sized` | `abi::tests::an_older_headers_subscription_options_are_filled_within_their_size`, `a_16_byte_struct_is_read_by_its_size` (an exactly 16-byte, 4-aligned allocation read by `karyos_client_add_subscription_with`), `an_older_headers_stream_options_are_filled_within_their_size` (no driver) |
| A caller's sized struct of another minor version (test support: `SizedStruct` in `tests/support/abi.rs`) | the conformance runner | `tests/conformance.rs` `the_sized_struct_checks_see_writes`; the library's side is `a_struct_from_a_newer_header_is_read_and_written_by_its_prefix` |
| The thread rules' tests (`karyos.h`, Threads): claim buffer fills, an outcome handler that reads nothing, options init and `assume_init`, moves of handles across threads (test only: `abi::tests::threads`, `conflated::a_view_moves_between_threads`, `archive::a_connection_moves_between_threads`) | `karyos_publication_claim`, `karyos_claim_commit`, `karyos_publication_poll_outcomes`, `karyos_driver_options_init`, the closes | `archive::a_connection_moves_between_threads` runs under Miri. The others are driver integration, native only (below); their unsafe patterns are the classes above: the claim's staged buffer (`a_publication_offers_and_commits_staged_claims`), the outcome handler call (`records_reach_the_handler_which_cannot_reenter_its_publication`) and options init writes (`the_options_carry_their_size_and_the_drivers_defaults`) |
| The conformance runner's message handler: the message slice read, and a poll of its own subscription from inside it (test support: `keep_message` and `ignore` in `tests/support/abi.rs`) | the conformance runner | none under Miri: the conformance scenarios are native only (below). The library's side of both is covered: `abi::tests::a_subscription_delivers_each_message_from_its_private_copy` and `abi::tests::a_handler_that_reenters_its_subscription_is_refused` |
| The semantic adapter's claim fill: the message copied into a staged claim's buffer (test support: `publication_claim_filled` in `tests/support/abi.rs`) | `publication.publish_claimed` of the conformance runner | `tests/driver.rs` `a_claim_filled_by_its_caller_is_staged_until_its_abort`; the library's side, the caller writing through the claim's `*mut u8` and the commit loading it, is `abi::tests::a_publication_offers_and_commits_staged_claims` |
| The `archive-replay` wrappers (B6-3): the replay options' init and read, the replay's out-parameters and `detail`, the replay subscription's, the subscription end's sized struct (test support: `replay_options`, `archive_replay`, `archive_stop_replay`, `client_add_replay_subscription`, `subscription_end_state` in `tests/support/abi.rs`) | the conformance runner's `archive.*`, `replay.subscribe` and `subscription.end` ops | `tests/abi.rs` `the_replay_wrappers_pass_their_pointers` (no driver) |
| The recording handler that keeps each recording's id and position (test support: `keep_recording` and `archive_recordings` in `tests/support/abi.rs`) | the conformance runner's `archive-replay` provisioning | none under Miri: the provisioning runs natively, on Linux only. The library's side of the handler call is `abi::tests::archive::a_listing_pages_through_the_catalog_after_an_id` |

## What Miri does not cover

- **Driver integration flows**, the tests tagged with the reason above.
  They exercise the driver and the facade through the ABI, not an unsafe
  site the table lacks, and run natively on macOS and Linux.
- **The cross-process client** (`RemoteClient`, Linux only): shared
  mappings, descriptors and syscalls are outside Miri. The Linux tests
  of `karyos-client`, `karyos-driver` and `tests/connect.rs` cover them,
  including a remote client's guarded publication (`tests/outcomes.rs`)
  and conflated view.
- **Network images** (UDP sockets):
  `a_network_subscription_grows_its_copy_with_a_larger_image` and
  `a_retired_images_change_carries_its_end` run natively, and so does
  the image change's populated write (`has` = 1), which only a network
  image produces. Under Miri, `has` = 0 runs, and the populated write
  runs driverless through `write_image_change`.
- **Real C callers.** Miri calls the exports from Rust. The header check
  (`src/header.rs`) and the conformance runner (`tests/conformance.rs`)
  cover the C declarations; a binding's own runner covers its language.
- **The conformance scenarios.** They read the suite's files, which
  Miri's isolation refuses, and with isolation disabled they exceed the
  budget. They run natively; their unsafe parts are covered above.
- **Timing.** Miri's clock and scheduling are not the native ones; a
  test that depends on them is native only.
- **Deliberate leaks.**
  `boundary::tests::a_payload_that_always_panics_on_drop_is_given_up`
  forgets its payload on purpose and is ignored under Miri.
- **Stress loops.** `handles::tests::stale_uses_never_make_the_live_handle_busy`
  is a stress loop, native only.

## Running it

```sh
make miri                                  # karyos-sys, then this crate
cargo +nightly-2026-10-11 miri test -p karyos-ffi --locked
```

A PR's record states the toolchain, the exact head, the command, the
test counts with the ignored ones, and the wall time.

### Sharded runs

Under Miri the tests run one at a time, so on a loaded host the single
run above can take hours. A run may be split into shards instead, by a
rule a third party can repeat without asking which tests went where:

1. List the library's tests, sorted bytewise:
   `cargo +nightly-2026-10-11 miri test -p karyos-ffi --lib --locked -- --list`,
   keeping the names of the lines that end in `: test`, under
   `LC_ALL=C sort`.
2. Give the `i`-th name, counting from 0, to library shard `i mod N + 1`.
   Each library shard runs
   `cargo +nightly-2026-10-11 miri test -p karyos-ffi --lib --locked -- --exact <its names>`.
3. One more shard runs the integration tests:
   `cargo +nightly-2026-10-11 miri test -p karyos-ffi --locked --test abi --test conformance --test connect --test driver --test outcomes`.
   `connect` and `outcomes` are Linux only and run nothing on macOS, as
   the cross-process client is outside Miri (above).
4. Each shard may use a target directory of its own, so the shards do
   not wait for one another's build lock.

The evidence is the union of the shards. Its record states `N`, each
shard's counts, wall time and exit code, and that the names the library
shards ran are exactly the sorted list of step 1, none missing and none
twice.
