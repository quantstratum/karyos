### Changed

- `karyos-trace` is publishable (`publish = true`, a README) and joins the crates.io set from the next alpha, after `karyos-protocol`, for karyos-insights (ADR-0068, INS-Q4). Its analysis surface, the trace report, journal sources, histograms and clock calibration and the types their signatures name, is supported in alpha; the rest of the crate, its writers, collectors, agents, sampling and trace clocks, stays internal and unstable (karyos#997).
