// SPDX-License-Identifier: Apache-2.0

//! `karyos-tiering`: offline tiering of an Archive directory
//! (ADR-0104; karyos#1113). See [`karyos_tiering::tool`].

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut out = std::io::stdout();
    let code = karyos_tiering::tool::run(&args, &mut out);
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
