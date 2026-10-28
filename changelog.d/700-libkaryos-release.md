### Added

- The release tooling of libkaryos as its own artifact, separate from
  karyosd (owner item 44, karyos#700): `scripts/release-libkaryos.sh`
  builds the library package and the karyosd artifact as two tarballs
  with `SHA256SUMS`; `scripts/sign-release.sh` signs them with key-based
  cosign (no key exists yet, so it refuses); `scripts/conformance-package.sh`
  runs the conformance suite against a released tarball rather than the
  build tree. The package's MANIFEST says `contents=library` and
  `excludes=karyosd`; the conformance test kit says it is not a release
  package.
- The ABI manifest of the C header (`scripts/abi-manifest.sh`): every
  public struct's size, alignment and field offsets and every constant,
  measured by compiling the header. It ships as
  `share/karyos/abi-manifest.txt`, and `make abi-manifest-check`, in
  pre-push, fails a layout change without a new ABI version.
- The soname policy is owner item 48's ruling (`0.y` before 1.0), no
  longer an interim note.
