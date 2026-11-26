// SPDX-License-Identifier: Apache-2.0

//! `karyos-tools`: subcommands that read Karyos's files offline, and
//! `probe` (Linux; R-CORE-35), a driver's readiness for an orchestrator's
//! probe, whose logic is in `karyos_tools::probe`. The offline one is
//! `replay diff` (`quantstratum-docs:
//! karyos/design/recording-group-replay.md` section 10), the alias of
//! `karyos-replay diff` (`karyos/design/archive-host.md`, H5), whose logic
//! is in [`karyos_tools::replay`]. See `karyos-tools replay diff --help`.

use std::io::Write;
use std::process::ExitCode;

use karyos_tools::replay;

/// The usage text of `karyos-tools --help`.
const HELP: &str = "\
karyos-tools: subcommands that read Karyos's files offline.

Usage: karyos-tools replay diff ...   (see karyos-tools replay diff --help)
       karyos-tools probe --dir <dir>  (Linux; see karyos-tools probe --help)
       karyos-tools compat <FROM> <TO> (see karyos-tools compat --help)
       karyos-tools calibrate phc ...  (Linux; see karyos-tools calibrate --help)
       karyos-tools upgrade-evidence ... (see karyos-tools upgrade-evidence --help)

`karyos-tools replay diff` is `karyos-replay diff` by another name.
";

/// How the alias names the diff.
const DIFF: &str = "karyos-tools replay diff";

fn main() -> ExitCode {
    // R-CORE-33: `--versions` before anything else, touching no driver.
    if let Some(code) = karyos_tools::versions::intercept(std::env::args_os().skip(1)) {
        return code;
    }
    let mut args = std::env::args_os().skip(1);
    let (command, sub) = (args.next(), args.next());
    match (text(command.as_ref()), text(sub.as_ref())) {
        // A command that is not UTF-8 is no command: an error, not help.
        (Some(None), _) | (_, Some(None)) => fail(&"an argument is not UTF-8"),
        (Some(Some("replay")), Some(Some("diff"))) => ExitCode::from(replay::run_diff(
            DIFF,
            args,
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        )),
        #[cfg(target_os = "linux")]
        (Some(Some("probe")), _) => ExitCode::from(karyos_tools::probe::run(
            sub.into_iter().chain(args),
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        )),
        #[cfg(target_os = "linux")]
        (Some(Some("calibrate")), _) => ExitCode::from(karyos_tools::calibrate::run(
            sub.into_iter().chain(args),
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        )),
        (Some(Some("compat")), _) => ExitCode::from(karyos_tools::compat::run(
            sub.into_iter().chain(args),
            &mut std::io::stdout().lock(),
            &mut std::io::stderr(),
        )),
        (Some(Some("upgrade-evidence")), _) => ExitCode::from(karyos_tools::upgrade_evidence::run(
            sub.into_iter().chain(args),
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        )),
        (Some(Some("replay")), None | Some(Some("-h" | "--help"))) => {
            let _ = std::io::stdout().write_all(replay::help(DIFF).as_bytes());
            ExitCode::SUCCESS
        }
        (None | Some(Some("-h" | "--help")), _) => {
            let _ = std::io::stdout().write_all(HELP.as_bytes());
            ExitCode::SUCCESS
        }
        _ => fail(&"unknown subcommand (karyos-tools --help lists them)"),
    }
}

/// An argument as text: `Some(None)` when it is not UTF-8.
fn text(arg: Option<&std::ffi::OsString>) -> Option<Option<&str>> {
    arg.map(|arg| arg.to_str())
}

/// Prints one error line and returns status 3.
fn fail(error: &dyn std::fmt::Display) -> ExitCode {
    let _ = writeln!(std::io::stderr(), "karyos-tools: {error}");
    ExitCode::from(replay::EXIT_ERROR)
}
