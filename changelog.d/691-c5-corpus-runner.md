### Added

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
