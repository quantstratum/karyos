### Added

- `karyos-tiering`, the Archive's object storage client (SPEC.md §8.4, "Tiered storage"; part of karyos#965), under the object storage admission record:
  - `S3Store` implements `karyos_archive::integrity::tiering::ObjectStore` over S3, signing each request with `rusty-s3` 0.11.0 (`graviola`) and sending it with `hyper`'s HTTP/1.1 client over `tokio-rustls`, TLS 1.3 only, with the server verified against the configured roots.
  - It writes under object-lock `COMPLIANCE` retention when configured, and checks the TLS provider's CPU requirements first.
  - The crate is not a default member, `karyos-archive` does not depend on it, and `make tiering-graph-check` (in `pre-push`) runs the record's `cargo tree` checks: no client crate in a data-path or default graph, and no native crypto or C build in its own.
