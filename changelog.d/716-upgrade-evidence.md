### Added

- The rolling-upgrade evidence of SPEC.md §9's third rule (karyos#716).
  - **One command:** `scripts/upgrade-evidence.sh <old-rev> <new-rev> <log-dir>` builds `karyos-tools` at both revisions and first requires `karyos-tools compat` to decide interoperate in both directions on the two `--versions` objects. It then replays the recorded Cluster log and each seed's generated sequence with each binary, then compares every pair with `karyos-replay diff`. It fails on any difference and records the log, both revisions, the seeds, both compat decisions and every result in `evidence.txt`.
  - **`karyos-tools upgrade-evidence`:** `replay`, `generate` and `record` write recording group journals: one event per entry, holding the payload and the typed outcome, then the composed snapshot.
  - **Differential test:** the generator draws unknown command types, unknown schemas, schema 2 and 5 versions no build writes, unknown templates, and bytes that are no message. A version 1 and a version 2 binary agree on every seed, and each deliberate semantic change diverges, in process and through the diff.
  - **Limits:** the procedure states the diff's comparison limits (an output compared by length and CRC-32C; outcomes compared as text) with no normalisation: every field of every outcome is compared.
