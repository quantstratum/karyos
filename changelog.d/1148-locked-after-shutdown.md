### Changed

- Tests: a loop test pins that an Archive shutdown releases a sealed group directory's integrity journal lock before it returns, and the `karyos-tools` verify tests retry every integrity journal open on `Locked`, which a sibling test's child process could hold for the instant between its fork and exec (karyos#1148).
