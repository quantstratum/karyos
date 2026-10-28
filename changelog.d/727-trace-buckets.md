### Added

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
