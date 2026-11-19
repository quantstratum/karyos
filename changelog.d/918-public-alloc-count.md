### Added

- `karyos::alloc_count` (facade feature `alloc-count`): a counting global allocator a product-layer test profile installs to check that a call allocates, reallocates and frees nothing on the calling thread, with no `unsafe` and no internal crate. `karyos-sys`'s `alloc_count` moves from `test-hooks` to its own `alloc-count` feature, which `test-hooks` still includes (R-CORE-48, karyos#918).
