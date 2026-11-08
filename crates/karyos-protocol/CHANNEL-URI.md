<!-- SPDX-License-Identifier: Apache-2.0 -->

# Channel URI grammar

This file records the grammar of a channel URI as `ChannelConfig::parse`
(`src/channel.rs`) accepts it, and the rules every new key follows. It is
the grammar the common URI rule of the owner decisions of 2026-10-21
requires before a key is implemented (`quantstratum-docs:
owner-decisions/2026-10-21/decisions.md`, "Common URI rule"); SPEC.md §5
lists the parameters and their meaning. Examples illustrate the grammar;
the ABNF ([RFC 5234](https://www.rfc-editor.org/rfc/rfc5234)) and the
rules are the definition.

A change that adds or changes a key updates this file in the same pull
request. A test reads this file and fails when a key of the parser's
`KEYS` table is missing from the key table below.

## 1. Structure

```abnf
channel-uri  = "karyos:" media [ "?" query ]
media        = "ipc" / "udp"
query        = parameter *( "|" parameter )
parameter    = key "=" value
key          = 1*( %x21-3C / %x3E-7B / %x7D-7E )   ; matched against the key table
value        = 1*( %x21-7B / %x7D-7E )             ; any visible ASCII except "|"
```

- The URI is at most 2048 bytes (`MAX_URI_LENGTH`), counted before any
  other check. Longer is `TooLong`. A client command carries at most 512
  bytes of URI (`cnc::MAX_COMMAND_URI`), so a URI sent to a driver through
  the command path is refused above that by the client first.
- Everything is case sensitive: `karyos:UDP`, `Endpoint=` and
  `reliable=TRUE` are refused.
- There is no escaping and no percent encoding. `|` cannot appear in a
  value. The first `=` of a parameter ends the key, so a later `=` belongs
  to the value, where no value rule below admits it.
- An empty query (`karyos:ipc?`), an empty parameter (`a=1||b=2`, a
  trailing `|`), a parameter without `=` and an empty value are
  `Malformed`. A key not in the key table is `UnknownParameter`.
- `karyos:udp` without a query has no parameters, and is refused for
  having no destination (section 4).
- Characters outside the ABNF above, spaces included, are refused by the
  value rule of the key they appear in, or as an unknown key.

## 2. Key names

```abnf
key-name     = word *( "-" word )
word         = lower *( lower / DIGIT )
lower        = %x61-7A
```

Every key is kebab-case: words of lower-case ASCII letters and digits,
each starting with a letter, joined by single hyphens (`a1-b2` is a key
name, `a-1b` is not). The parser checks this at compile time for every
entry of `KEYS`, so a key that breaks it does not build. Each setting has exactly one spelling: there are no aliases,
no case folding and no `_` forms, so `term_length=` is an unknown key, not
a second spelling of `term-length`.

## 3. Cardinality and repetition

- A key appears at most once in a URI. A second occurrence is `Repeated`,
  whatever its value, even an equal one.
- A list value separates its elements with `;`. Every element is
  non-empty and valid on its own; an empty element is refused by the
  element rule. A list has a bound stated by its key, and the same element
  twice is refused as `InvalidValue`.
- **Two spellings of one element repeat it.** Elements are compared in a
  canonical form: an IPv4-mapped IPv6 address is the IPv4 address it
  maps, so `destinations=10.0.0.5:1;[::ffff:10.0.0.5]:1` and
  `paths=10.0.0.7;::ffff:10.0.0.7` are refused as repetitions. A socket
  address is compared by canonical address, port and IPv6 zone, so
  `[fe80::1%1]:1` and `[fe80::1%2]:1` are two elements. An interface name
  is compared byte for byte. The parsed element is kept as written. Before
  this rule (0.1.0-alpha.2) a mapped and an unmapped spelling of one
  address were accepted as two elements.
- Ordering of parameters carries no meaning.
- A URI with several problems reports one of them. Which one is not part
  of the contract; a URI with exactly one problem reports that problem.

## 4. Existing keys

These sixteen keys are the published forms. Their syntax, values and
refusals below are a compatibility contract: a change may add keys, but
must not change what one of these accepts or the value it parses to. The
one change since 0.1.0-alpha.2 is the repetition rule of section 3, which
refuses a list naming one address in two spellings.
`channel::tests::published_keys_keep_their_meaning` asserts one case for
each key of `KEYS`, matching on every `Key` variant, so a new key does not
compile without its own case.

| Key | Media | Value |
| --- | --- | --- |
| `endpoint` | udp | `socket-address`; not multicast |
| `group` | udp | `socket-address`; multicast |
| `interface` | udp | `interface` |
| `mtu` | ipc, udp | `decimal`, at most 8192, with room for a frame header and payload |
| `term-length` | ipc, udp | `decimal`, a power of two from 65536 to 1073741824 |
| `reliable` | udp | `true` or `false`; default `true` |
| `paths` | udp | 1 to 4 `interface` elements separated by `;`, none repeated |
| `lanes` | ipc, udp | `decimal`, 1 to 4 |
| `guard` | ipc, udp | 1 to 64 bytes of `A-Z a-z 0-9 . _ -` |
| `trace` | ipc, udp | `off`, `all` or `sampled:` `decimal`, at least 1 |
| `fc` | udp | `min`, `max` or `tagged:` `decimal` (a `u64`, 0 included) |
| `security` | udp | `trusted`; `authenticated` and `encrypted` are `SecurityUnsupported` |
| `destinations` | udp | 1 to 64 `socket-address` elements separated by `;`, none multicast, none repeated |
| `control` | udp | `socket-address`; not multicast |
| `control-mode` | udp | `manual` or `dynamic` |
| `ttl` | udp | an integer from 1 to 255, see below |

```abnf
decimal        = "0" / ( %x31-39 *DIGIT )   ; no sign, no leading zero
interface      = interface-addr / interface-name
interface-addr = IPv4address / IPv6address  ; RFC 3986, no brackets, no zone
interface-name = 1*15( ALPHA / DIGIT / "." / "_" / "-" )
socket-address = IPv4address ":" port
               / "[" IPv6address [ "%" zone-id ] "]" ":" port
port           = 1*DIGIT                    ; value 1 to 65535
zone-id        = 1*DIGIT                    ; value 0 to 4294967295
```

`IPv4address` and `IPv6address` are those of [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2)
section 3.2.2: dotted decimal without leading zeros, and the RFC 4291 text
forms of IPv6 with `::` compression, hexadecimal in either case, and an
embedded IPv4 tail. The parser reads addresses with Rust's
`std::net::SocketAddr` and `IpAddr`, which define the accepted text where
the two differ. Rules on top of the syntax:

- **IPv6.** A socket address puts an IPv6 address in brackets, so
  `[::1]:40123` parses and `::1:40123` is refused. A zone is a numeric
  scope id only (`[fe80::1%2]:40123`); an interface name as zone is
  refused. An `interface` is an unbracketed address and carries no zone.
  An IPv4-mapped address (`[::ffff:10.0.0.5]:1`) is accepted and kept as
  written; in a list it repeats its IPv4 spelling (section 3).
- **Ports.** Port 0 is refused on every existing key. A port may have
  leading zeros (`:040123` is port 40123); this is the address parser's
  syntax and is part of the published form.
- **Unspecified addresses.** `0.0.0.0` and `::` are refused in a socket
  address. An `interface` may be unspecified.
- **Multicast.** `group` must be a multicast address; `endpoint`,
  `control`, each `destinations` element and an `interface` must not.
- **`ttl` syntax.** `ttl` predates the `decimal` rule and is read as a
  Rust `u8`: an optional `+` and leading zeros are accepted (`ttl=+01` is
  1). This leniency is a published form and stays; no new key copies it.

Rules between keys:

- **`ipc`** accepts only `mtu`, `term-length`, `lanes`, `guard` and
  `trace`. Any other known key on `ipc` is `NotApplicable`.
- **Destination.** A `udp` channel names exactly one destination form:
  `endpoint` alone (unicast), `group` alone (multicast), or `destinations`
  and `control`, one or both (multi-destination). None, or keys of two
  forms, is `Destination`.
- **`ttl`** applies only with `group`; **`control-mode`** only to
  multi-destination; **`fc`** only to multicast and multi-destination.
  Elsewhere each is `NotApplicable`.
- **`control-mode`.** Without the key, the mode is `dynamic` when
  `control` is present and `manual` otherwise. `dynamic` without
  `control` is a `Conflict` of `control-mode` and `control`. `manual`,
  given or defaulted, without `destinations` is a `Conflict` of
  `control-mode` and `destinations`.
- **`interface` and `paths`** together are a `Conflict`.

## 5. Rules for new keys

The common URI rule binds every key added after the sixteen above.

- **Name.** Kebab-case, by section 2. One spelling.
- **Single source.** A setting is given by one key. When a new key covers
  something an existing key or another new key already expresses, the URI
  that gives both is refused with `Conflict`, naming both keys; it is never
  resolved by precedence. A key that overrides a driver setting for one
  channel is an override, not a conflict; until a key is implemented, the
  driver setting stays and the key is an unknown parameter.
- **Integers** use `decimal`. A key states its range and unit, if any, in
  the key table.
- **Durations** use the duration grammar below.
- **Addresses** use `socket-address` or `interface` as defined in
  section 4, with the same IPv6, unspecified and multicast rules. Port 0
  stays refused unless the key's own rule admits it for a named role, and
  the key's tests cover the roles where it is refused.
- **Lists** use `;`, state a bound, and refuse a repeated element,
  compared in the canonical form of section 3.
- **Reserved characters.** `|`, `=` and `;` have the meanings above. `@`
  and `,` are reserved for structured list elements (such as an interface
  paired with an endpoint); a key that uses one records its element
  grammar here. No key uses `%` except as the IPv6 zone separator.
- **Refusals.** A new key's refusals are typed `ChannelError` values:
  `Repeated`, `NotApplicable`, `Conflict`, `InvalidValue`, or
  `InvalidDuration` for a duration.

### Keys added under this rule

| Key | Media | Value |
| --- | --- | --- |
| `retransmit-window` | udp | `decimal` bytes: positive, a multiple of 32, at most `term-length` / 2; default `term-length` / 2 |

- **`retransmit-window`** (owner item 63) is fixed at channel creation and
  overrides the driver's repair setting for that channel. It applies only
  to a reliable channel: with `reliable=false` it is a `Conflict` of
  `reliable` and `retransmit-window`. When the URI gives `term-length`, a
  window above half of it is `InvalidValue` at parse time; otherwise the
  driver refuses it, typed, against the stream's term when it creates the
  publication. It is how far below its sent position the publication
  keeps its lanes for repair: the reliable-network held floor without
  required receivers is `sent` minus the window. A smaller window can
  make a hole unrecoverable even for a counted receiver; that loss is
  reported, never silent.

### Durations

```abnf
duration     = decimal unit
unit         = "ns" / "us" / "ms" / "s"
```

`channel::parse_duration` implements this rule and returns a
`std::time::Duration`.

- The unit is required: `linger=5` is `MissingUnit`.
- Units are exactly `ns`, `us`, `ms` and `s`, lower case. `m`, `min`,
  `sec`, `µs`, `S`, a space before the unit and any fraction or exponent
  are `UnknownUnit` (`5m`, `5 s`, `1.5s`, `1e3ms`).
- The number is a `decimal`: no sign and no leading zero, so `05s` and
  `+5s` are `NotDecimal`, as is a unit with no number (`ms`). `0s` is
  zero.
- The value is converted to nanoseconds with checked arithmetic and must
  fit in a `u64` (about 584 years). A number too large for a `u64`, or a
  product that overflows, is `Overflow`: `99999999999s` is refused, never
  wrapped or saturated.
- Each duration key states its range (for example 0 to 60 s), compares
  the converted value against it, and refuses a value outside it with
  `InvalidValue`. Different spellings of one value (`1s`, `1000ms`) are
  the same value, not a conflict.

A key with a duration value reports a grammar refusal as
`ChannelError::InvalidDuration`, naming the key and carrying the
`DurationError`.

## 6. Pending extensions

Paired unicast path endpoints (`paths` elements of the form
interface `@` endpoint, owner item 11) extend the `paths` key and are
recorded here by the change that implements them, with their IPv6,
cardinality and conflict rules, before any code accepts them. Until then,
an `@` in a `paths` element is refused as an invalid interface.
