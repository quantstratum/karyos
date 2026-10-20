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
| Options init writes (F5) | `karyos_driver_options_init`, `karyos_stream_options_init` | `tests/driver.rs` `the_options_carry_their_size_and_the_drivers_defaults`, `a_stream_is_added_and_removed_through_the_abi` |
| Driver out-parameters and detail (F5) | `karyos_driver_create`, `_do_work`, `_connect`, `_add_stream` | `tests/driver.rs` `a_struct_below_the_first_size_is_refused`, `a_refused_configuration_fills_nothing_but_the_status`, `a_client_of_the_driver_is_served_and_follows_its_close`, `a_stream_is_added_and_removed_through_the_abi` |
| The outcome handler call: a local `karyos_outcome`, valid for the call; reentry refused (F7a-2) | `karyos_publication_poll_outcomes` | `abi::tests::outcomes::records_reach_the_handler_which_cannot_reenter_its_publication` |
| The outcome poll's arguments and `delivered` write, checked before the handle (F7a-2) | `karyos_publication_poll_outcomes` | `abi::tests::outcomes::the_arguments_are_checked_before_the_handle` |
| The timed offer's payload slice (F7a-3) | `karyos_publication_offer_at` | the `timed_offer_checks` tests of `abi::tests` |
| The clock's `now` write; nothing written on refusal (F7a-3) | `karyos_clock_now` | the `clock` tests of `abi::tests` (Monotonic; a TAI read is native only) |
| A caller's sized struct of another minor version (test support: `SizedStruct` in `tests/support/abi.rs`) | the conformance runner | `tests/conformance.rs` `the_sized_struct_checks_see_writes`; the library's side is `a_struct_from_a_newer_header_is_read_and_written_by_its_prefix` |

## What Miri does not cover

- **Driver integration flows**, the tests tagged with the reason above.
  They exercise the driver and the facade through the ABI, not an unsafe
  site the table lacks, and run natively on macOS and Linux.
- **The cross-process client** (`RemoteClient`, Linux only): shared
  mappings, descriptors and syscalls are outside Miri. The Linux tests
  of `karyos-client`, `karyos-driver` and `tests/connect.rs` cover them.
- **Network images** (UDP sockets):
  `a_network_subscription_grows_its_copy_with_a_larger_image` runs
  natively.
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
