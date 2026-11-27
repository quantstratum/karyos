### Fixed

- `cargo test -p karyos-cluster` without the `backup` feature builds again: the rebuild identity's vector test runs only with `backup`, as the derivation does (ADR-0123, karyos#717).
