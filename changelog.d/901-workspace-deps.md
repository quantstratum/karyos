### Removed

- The unused `karyos-feed` and `karyos-bench` aliases in the root
  `[workspace.dependencies]`, which made Cargo warn
  (`cargo::unused_workspace_dependencies`) under the pinned Miri
  toolchain (karyos#901). No member used either.
