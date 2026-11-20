### Changed

- The agent seals an unsealed operations journal in chunks of at most 1 MiB, each read and sealed on its own, instead of reading it whole on its first seal (karyos#1071).
