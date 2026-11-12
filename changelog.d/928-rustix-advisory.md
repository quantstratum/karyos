### Security

- `rustix` is updated from 1.1.5 to 1.1.6 in `Cargo.lock` (karyos#928),
  the fixed release for RUSTSEC-2026-0486 (the `rustix::fs` xattr
  functions marked unwritten bytes as initialised on a zero-length
  buffer). No other crate moves; `linux-raw-sys` stays at 0.12.1.
