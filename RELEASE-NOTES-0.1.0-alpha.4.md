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

## libkaryos and karyosd

The first release of the C library as its own artifact (owner item 44,
karyos#700), attached to the GitHub release of `v0.1.0-alpha.4`, built by
`scripts/release-libkaryos.sh` at the tag for aarch64 and x86_64 Linux and
aarch64 macOS:

- `libkaryos-<abi>-0.1.0-alpha.4-<triple>.tar.gz`: the header, static and
  shared libraries, pkg-config files and the ABI manifest. Its MANIFEST
  says `contents=library` and `excludes=karyosd`: the library holds no
  daemon.
- `karyosd-0.1.0-alpha.4-<triple>.tar.gz`: the driver daemon alone
  (`contents=karyosd`, `excludes=libkaryos`).
- `SHA256SUMS` per host, the header's ABI version and the struct manifest
  (`abi-manifest-<abi>.txt`).

The soname carries `0.y` before 1.0 (`soname_policy=0y-exact`, owner item
48): a binding requires the exact `0.y` line and a library patch at least
its header's. The conformance test kit (`make libkaryos-testkit`) is not a
release package and is not attached.

**Unsigned.** The owner deferred signing on 2026-11-23: no release key
exists yet (karyos-deploy ADR-0003, D1 gates). Both MANIFESTs say
`signed=no`; verify the archives against `SHA256SUMS` only. A later release
signs them with `scripts/sign-release.sh`.

## Changes

See the `0.1.0-alpha.4` section of `CHANGELOG.md`.

## Evidence

| Check | Command | Platform | Head | Result |
| --- | --- | --- | --- | --- |
| The local gate | `CHANGELOG_RELEASE=1 make pre-push` | Linux 7.0.0-43-generic, x86_64 host flumix (not macOS: the team's gate pool) | `7d43d878` | 255 test suites, 6069 passed, 0 failed, 37 ignored; exit 0 |
| The Linux tests | `scripts/linux-test.sh --workspace --all-features --locked --no-fail-fast` (volume `karyos-linux-target-issue1033-7d43d878`) | Docker on studiom4, Linux kernel 6.8.0-117-generic, aarch64 | `7d43d878` | 206 test suites, 5796 passed, 0 failed, 36 ignored; exit 0 |

The release tree differs from `7d43d878` only in this file (its Evidence rows). The joint `cargo publish --dry-run`, the scratch project build and the libkaryos artifacts' conformance runs are recorded after the tag, as dated rows.

### Written exception

As for 0.1.0-alpha.3, this release is not gated by every gate of
`RELEASING.md`. The owner authorised the publication on 2026-11-23 with
`CHANGELOG_RELEASE=1 make pre-push` and the full Linux run as its gates
while hosted CI is off (karyos#623). These gates were **not run** for it:
`make loom-full`, both Miri halves, `make sim`, Clippy with every feature
in Docker Linux (pre-push's `lint-linux` runs it on macOS for
`aarch64-unknown-linux-gnu`), the network impairment suite, the C library
package, the binding conformance suite and the wire compatibility matrix.
`libkaryos` and `karyosd` are released unsigned (see "libkaryos and
karyosd"); the C ABI manifest is committed as the released ABI 0.1.7's,
`crates/karyos-ffi/abi/released/0.1.7.txt`. This exception covers
0.1.0-alpha.4 only.
