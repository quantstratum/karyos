### Changed

- The codec derive refuses, at compile time, two fixed fields whose byte ranges overlap (naming both) and a field past its template's block length (karyos#1066).
