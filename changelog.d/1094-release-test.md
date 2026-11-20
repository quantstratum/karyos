### Fixed

- `a_release_that_clears_nothing_is_an_error` calls the inherent `ImmutableAttribute::release`, which refuses a file system with no attribute, and checks the backend's release separately (nothing to release there: `Ok`); both go through one clearing function. It failed in Linux Docker since karyos#995 (karyos#1094).
