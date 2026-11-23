<!-- SPDX-License-Identifier: Apache-2.0 -->

# Karyos 0.1.0-alpha.4

Released 2026-11-23. The second crates.io publication. It adds `karyos-trace`
to the published crates for karyos-insights (ADR-0068, INS-Q4; karyos#997,
karyos#1033).

## Published crates

In dependency order: `karyos-sys`, `karyos-protocol`, `karyos-trace`,
`karyos-codec`, `karyos-client`, `karyos-io`, `karyos-archive`,
`karyos-cluster`, `karyos`. Depend on them by the exact pre-release, for
example `karyos = "=0.1.0-alpha.4"` or `karyos-trace = "=0.1.0-alpha.4"`; a
Cargo pre-release does not match a plain `0.1` requirement. Every other
crate keeps `publish = false`.

## Supported API

The `karyos` facade, `karyos-client` and `karyos-archive`, as in
0.1.0-alpha.3, plus the C ABI under its own `0.y.z` rule; and, new in this
release, the analysis surface of `karyos-trace`:

- the report: `TraceReport` and the `report` module, with `TraceAnswer`,
  `PublicationSummary`, `PublicationKey`, `JournalClock`, `JournalId`,
  `HeldMessage` and `HistogramConfig`;
- journal sources: the `JournalSource` contract of the `source` module,
  with `SourceState` and `SourceLosses`;
- histograms: `Histogram` and its merge, with `HistogramCounts`,
  `SideCounts`, `Quantile` and `HistogramError`;
- clock calibration: `Calibration` and `latency` of the `clocks` module,
  with `Latency`, `ClockKey`, `Observation`, `CalibrationError` and
  `Unavailable`;
- and the types those signatures name, as listed in the crate's
  documentation ("Support").

The rest of `karyos-trace` (its writers, collectors, agents, sampling and
trace clocks) is internal and unstable. Every other published crate is
internal and unstable in alpha with no compatibility promise. Supported or
not, alpha APIs, wire formats, shared-memory layouts and the C ABI will
change.

## Compatibility with 0.1.0-alpha.3

The admission protocol version is 4 (`KARYOS_PROTOCOL_VERSION` 4, C ABI
0.1.7): a client or driver of 0.1.0-alpha.3 (version 3) is refused at
admission with the typed `IncompatibleVersion`. Upgrade clients and the
driver together.

## Dependencies

The published graph gains the ADR-0086 wire authentication and ADR-0051
archival integrity families: `sha2`, `hmac` and `zeroize` through
`karyos-protocol` (owner decision D51, quantstratum-docs#990) and
`ed25519-dalek` with `sha2` through `karyos-archive` (owner decision ACS
71206). The admission review is in `RELEASING.md`, "Admission review of the
published graph".

## Changes

See the `0.1.0-alpha.4` section of `CHANGELOG.md`.

## Evidence

| Check | Command | Platform | Head | Result |
| --- | --- | --- | --- | --- |
| The local gate | `CHANGELOG_RELEASE=1 make pre-push` | macOS arm64 (studiom4) | PENDING | PENDING |
| The Linux tests | `scripts/linux-test.sh --workspace --all-features --locked --no-fail-fast` | Docker, Linux | PENDING | PENDING |

### Written exception

As for 0.1.0-alpha.3, this release is not gated by every gate of
`RELEASING.md`. The owner authorised the publication on 2026-11-23 with
`CHANGELOG_RELEASE=1 make pre-push` and the full Linux run as its gates
while hosted CI is off (karyos#623). These gates were **not run** for it:
`make loom-full`, both Miri halves, `make sim`, Clippy with every feature
in Docker Linux (pre-push's `lint-linux` runs it on macOS for
`aarch64-unknown-linux-gnu`), the network impairment suite, the C library
package, the binding conformance suite and the wire compatibility matrix.
No `libkaryos` or `karyosd` artifact is released (no release key, see
"libkaryos and karyosd artifacts"), so the C ABI manifest is not copied
to `crates/karyos-ffi/abi/released/`. This exception covers
0.1.0-alpha.4 only.
