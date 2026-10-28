### Added

- The release tooling of libkaryos as its own artifact, separate from
  karyosd (owner item 44, karyos#700): `scripts/release-libkaryos.sh`
  builds the library package and the karyosd artifact as two tarballs
  with `SHA256SUMS`, deterministic on a host whatever its TZ and umask
  (`scripts/check-release-reproducible.sh`); `scripts/sign-release.sh`
  signs exactly what `SHA256SUMS` lists with key-based cosign and a
  `pkcs11:` key only (no key exists yet, so it refuses); `scripts/conformance-package.sh`
  runs the conformance suite against a released tarball rather than the
  build tree. The package's MANIFEST says `contents=library` and
  `excludes=karyosd`; the conformance test kit says it is not a release
  package.
- The ABI manifest of the C header (`scripts/abi-manifest.sh`): every
  public struct's size, alignment and field offsets and every constant,
  measured by compiling the header, and every other declaration as
  written. It ships as `share/karyos/abi-manifest.txt`, and
  `make abi-manifest-check`, in pre-push, fails a header that no longer
  matches it, or a change since the last released manifest
  (`crates/karyos-ffi/abi/released/`) without a higher ABI version.
- The soname policy is owner item 48's ruling (`0.y` before 1.0), no
  longer an interim note.
