<!-- SPDX-License-Identifier: Apache-2.0 -->

# SBE 1.0 golden vectors (karyos#646)

Two messages of Real Logic's public example schemas, encoded by the
reference SBE tool and derived independently from the SBE 1.0
specification. Both agree byte for byte.

| File | Message | Schema | Bytes |
| --- | --- | --- | --- |
| `car-v0.hex` | `Car`, version 0 | `../../schemas/example-schema.xml` | 207 |
| `car-v1.hex` | `Car`, version 1 | `../../schemas/example-extension-schema.xml` | 224 |

Each file holds an SPDX line (`#`), then the message with its 8-byte
message header, as lowercase hex on one line. The values are those of `Vectors.java`.

## Schemas

`../../schemas/` holds `example-schema.xml`, `example-extension-schema.xml`
and `common-types.xml` verbatim, apart from an SPDX comment and a
provenance comment after the XML declaration, from `real-logic/simple-binary-encoding`
tag `1.42.0` (`sbe-samples/src/main/resources/`), Apache-2.0. Version 1
adds the optional `uuid` and `cupHolderCount` fields (`sinceVersion="1"`):
the schema version change. The messages exercise repeating groups, a
nested group (`performanceFigures.acceleration`), variable data in a group
entry and at message level, enums, a set, composites and constants.

## Reproducing the reference bytes

The reference tool stays out of the Cargo graph and out of CI. On a Linux
x86_64 host, in user space:

- JDK: Eclipse Temurin `jdk-21.0.13.1+2`,
  `OpenJDK21U-jdk_x64_linux_hotspot_21.0.13.1_2.tar.gz`, SHA-256
  `bb8a93f9ae6e7a693b2b721e85dbeff26ae1a77447985a8d7afcdd9c7cf6222e`.
- Tool: `uk.co.real-logic:sbe-all:1.42.0` from Maven Central,
  `sbe-all-1.42.0.jar`, SHA-256
  `f60becdb567519a2ed3824ffe285f93adb2159b39ede0b234fc8b1f13736236a`.

With the three schemas and `Vectors.java` in one directory:

```sh
java -Dsbe.output.dir=gen -Dsbe.xinclude.aware=true -jar sbe-all-1.42.0.jar \
    example-schema.xml example-extension-schema.xml
javac -cp sbe-all-1.42.0.jar -d classes $(find gen -name '*.java') Vectors.java
java --add-opens java.base/jdk.internal.misc=ALL-UNNAMED \
    -cp classes:sbe-all-1.42.0.jar Vectors
```

It prints `V1 <hex>` and `V2 <hex>`, equal to `car-v0.hex` and
`car-v1.hex`.

## Independent derivation

The teammate session `adr-deriver` derived both messages from the SBE 1.0
specification and the schema text alone, from a brief that carried the
schemas and values but no bytes and no code. Its bytes equal the reference
tool's for both vectors.
