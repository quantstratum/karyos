### Added

- Disjoint trace buckets (R-CORE-23, karyos#727). The agent's trace window
  keeps each closed slice as a bucket that shares no pair with any other,
  sparse, under `WindowConfig::max_bucket_bytes` (default 64 MiB, oldest
  evicted first; a bucket larger than the budget is not kept). The new
  API v1 request `KARYOS-AGENT 1 trace-buckets DIR FROM [COUNT [EPOCH]]`
  returns them with the window run's `epoch`, each lane as mergeable
  counts and each bucket's loss; reading consumes nothing, so any number
  of readers share them. Refusals are typed: `epoch changed`,
  `buckets expired`, `bucket over budget`. A reply stops at a whole
  bucket within 1 MiB and names the next one. `capabilities` lists
  `trace-buckets`; the view's trace counts add `buckets_evicted` and
  `buckets_over_budget`. The rolling `trace-window` view is unchanged.
- `karyos_trace::Histogram::counts` and `Histogram::from_counts`
  (`HistogramCounts`, `SideCounts`): a histogram's counts exported and
  rebuilt exactly, refusing another layout or unit (`Mismatch`) and
  inconsistent counts (`InvalidCounts`).
