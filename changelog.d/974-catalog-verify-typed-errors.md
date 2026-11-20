### Changed

- `karyos-catalog verify` returns typed errors (`VerifyError`, `UsageError`, `TrustError`, `StoreError`) that keep the path and the underlying error; they become text only at the command boundary, with the same messages and exit statuses (karyos#974).
