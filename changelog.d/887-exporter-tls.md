### Added

- `karyos-exporter` can serve `/metrics` over TLS 1.3 on any address, with `--tls-cert` and `--tls-key`, in a build with `karyos-agent`'s `exporter-tls` feature (off by default; `rustls` with the `rustls-graviola` provider). Without TLS it still binds loopback only, and the bearer token is kept (karyos#887).
