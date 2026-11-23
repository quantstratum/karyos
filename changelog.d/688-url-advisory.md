### Security

- `url` moves from 2.5.8 to 2.5.9 (with `form_urlencoded` 1.2.3) in the lockfile, for RUSTSEC-2026-0592: `Url::origin()` recursed once per nested `blob:` prefix and could overflow the stack. It reaches `karyos-tiering` through `rusty-s3`; `make deny` failed on it (found by the runtime admission check of karyos#688).
