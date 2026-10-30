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
