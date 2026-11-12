### Changed

- CI checks RustSec advisories with `cargo deny check advisories` in a new
  `Advisories` job, separate from the `Licences and sources` job so an
  advisory database update does not hide licence, ban or source results.
  `make pre-push` stays offline (karyos#933).
