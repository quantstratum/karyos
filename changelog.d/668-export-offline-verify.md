### Added

- `integrity::export::offline::verify_export` verifies an Archive export offline (ADR-0103 design section 5; karyos#668), with the external trust only:
  - **Integrity:** each carried journal is verified by the online verifier over the export's own records, so the outcomes are the online ones.
  - **Completeness:** registry, policy and binding rows and the time evidence entries are checked reciprocally against their seals; an omission is `OfflineError::Incomplete`.
  - **Anchored run:** only records up to the latest trusted anchored head grant trust, while retirements and revocations always count.
  - **Policies:** a policy is proven only through a recording binding; a class binding is reported unproven.
  - **Time:** a recording's time verdict is `met` only with full anchored coverage.
  
  The blind vectors X-5 to X-12 reach their expected verdicts.
