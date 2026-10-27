<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog fragments

A pull request records its changelog entry here, never in `CHANGELOG.md`,
so that open pull requests do not conflict in `[Unreleased]`. Each change
is one file, `changelog.d/<issue>-<slug>.md`, for example
`changelog.d/634-refresh-cycles.md`:

```markdown
### Added

- Conflation refresh and snapshot cycles (SPEC §7.1; karyos#634).
```

The file holds exactly one section header (`Added`, `Changed`,
`Deprecated`, `Removed`, `Fixed` or `Security`) and the entries under it,
written as they will read in `CHANGELOG.md`. A change with entries in two
sections uses two files. `make changelog-check` validates the fragments,
and `make pre-push` runs it.

At a release, `scripts/changelog-assemble.sh` folds the fragments into
`[Unreleased]`, after the entries already there, and deletes them
(`RELEASING.md`). Decided 2026-10-27 by QS-COORDINATOR under owner
delegation (Joaquín, 2026-10-26).
