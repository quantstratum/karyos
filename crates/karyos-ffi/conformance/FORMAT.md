<!-- SPDX-License-Identifier: Apache-2.0 -->

# Conformance scenarios, interim format 1

The language-neutral conformance suite of the C ABI (SPEC.md §10.2, §13;
ADR-0053, ADR-0067) lives here, beside `karyos-ffi`. Its final format is
an owner decision (owner item 46); this is the interim format the
`karyos-ffi` runner and the bindings use until then (quantstratum-docs:
`karyos/design/ffi-gap-analysis.md`, F6). A binding's runner can be
written from this file alone, with its language's standard library; the
Rust runner, `../tests/conformance.rs`, is the reference.

## Files

- `scenarios/*.kcs`: one scenario per file, UTF-8, read line by line. A
  file in `scenarios/` with another extension is a failure.
- `index.txt`: the coverage map from the §13 contract rows to scenario
  ids (Index, below).
- The status names come from `../include/karyos.h` (`#define KARYOS_OK`,
  `#define KARYOS_E_*`); a runner reads them from the header of the
  library it tests, never from a copy.

## Lines and tokens

Outside a quoted string, `#` starts a comment that runs to the end of
the line. A line that holds only whitespace or a comment is blank and is
ignored everywhere, before `format` too. Every other line is a keyword
followed by tokens.

Tokens are separated by runs of whitespace: spaces and tabs. A token is
a run of characters with no whitespace between them, in which a double
quote opens a quoted string that runs to the next unescaped double
quote. Inside a quoted string, whitespace and `#` are literal, and `\"`
and `\\` are the only escapes; any other backslash, or a line that ends
inside a string, is a failure. So `text="a # b"` is one token, the name
`text`, `=`, and the quoted value.

| Keyword | Tokens | Meaning |
| --- | --- | --- |
| `format` | `1` | The format version; the first line that is not blank |
| `id` | a name without whitespace | The scenario's id, unique in the suite |
| `abi` | `MAJOR.MINOR` | The ABI version the scenario needs |
| `covers` | one quoted string | The §13 contract row it checks, as `index.txt` names it |
| `call` | a function name, then `name=value` arguments | Calls the C function |
| `expect` | an optional status name, then `name=value` results | Checks the last call |

`format`, `id`, `abi` and `covers` come once each, in any order after
`format`, and all before the first `call`. Every `call` is followed by
exactly one `expect`, before the next `call`. A scenario has at least one
`call`. A `name=value` token splits at its first `=`, and a name given
twice in one line is a failure.

## Values

- An integer: decimal, optionally negative, within 64-bit signed range
  (`108`, `-1`). An argument whose C type is narrower (such as the
  `int32_t` `status`) and that does not fit it is a failure.
- `null`: a null pointer, for a pointer argument.
- A quoted string.
- `$name`: a variable. Variables live for one scenario and carry across
  its steps. In an `expect`, an unbound variable binds to the result,
  and a bound one is compared with it. In a `call`, a variable must be
  bound by an earlier `expect` of the same scenario.

## Calls

A runner passes every pointer argument a scenario does not name as a
valid pointer to a value it owns, and reads the results from there. A
scenario names an argument only to pass something else, such as `null`.
The arguments and results of each function are those of the header:

| Function | Arguments | Results |
| --- | --- | --- |
| `karyos_abi_version` | `major`, `minor`, `patch` (`null` only) | status, `major`, `minor`, `patch` |
| `karyos_status_message` | `status` (required) | `text` (no status) |
| `karyos_driver_create` | none: the options of `karyos_driver_options_init` | status, `driver` |
| `karyos_driver_connect` | `driver` (required) | status, `client` |
| `karyos_driver_do_work` | `driver` (required) | status, `work` |
| `karyos_driver_close` | `driver` (required) | status |
| `karyos_client_poll` | `client` (required) | status, `served` |
| `karyos_client_close` | `client` (required) | status |

A handle is an integer value, bound from a result (`expect KARYOS_OK
driver=$driver`) and passed back (`call karyos_driver_do_work
driver=$driver`).

A result named in an `expect` that the call did not write is a failure.

## Failures

A scenario fails, and is reported as failed, on any of these:

- an unknown `format`, keyword, function, argument or status name (a
  status name the header does not define);
- a header line repeated, missing, or after a `call`;
- a `call` without its `expect`, an `expect` without a `call`, or no
  `call` at all;
- a malformed token or value (Lines and tokens, Values);
- an unbound variable in a `call`;
- a status that differs from the `expect`'s, an `expect` with a status
  for a function that returns none, or one without a status for a
  function that returns one;
- a result that differs from the `expect`'s, or was not written.

## Versions

A runner compares each scenario's `abi` with `karyos_abi_version()` of
the library. A scenario runs when the major versions are equal and:

- before 1.0 (major 0), the minor versions are equal, because a `0.y`
  minor may break (ffi-gap-analysis.md §4.5);
- from 1.0 on, the scenario's minor is not newer than the library's,
  because minors only add.

Any other scenario is skipped, never reported as passed.

## Reporting

A runner reports every scenario id with one outcome: passed, failed or
skipped, and for a failure the file and line of the step that failed.
A binding release requires no failure and no skip at the ABI version it
targets (SPEC.md §13).

## Index

`index.txt` holds one row per line, with `#` comments and blank lines as
in scenarios:

```text
<row name>: <scenario id> [<scenario id> ...]
<row name>: pending <batch or reason>
```

The row name is the text before the first `:`, trimmed, not empty and
without `#`; rows are unique. After the `:` comes either one or more
scenario ids separated by whitespace, or `pending` followed by the
batch of ffi-gap-analysis.md (or the reason) that will cover the row.

The map is checked both ways, and any breach is a failure:

- every id a row lists names an existing scenario whose `covers` is that
  row;
- every scenario is listed by the row its `covers` names, so a scenario
  appears under exactly one row.
