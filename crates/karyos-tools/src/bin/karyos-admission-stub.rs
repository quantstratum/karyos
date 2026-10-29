// SPDX-License-Identifier: Apache-2.0

//! `karyos-admission-stub`: the conformance suite's incompatible driver
//! (`crates/karyos-ffi/conformance/FORMAT.md`, Incompatible driver), a
//! test-kit binary built only with the `test-hooks` feature.
//!
//! `karyos-admission-stub --dir <dir> --mode refuse|version` listens on
//! `<dir>` as a driver's admission socket does and answers every client's
//! `Hello` with the real admission codec: `refuse` with `Refused`
//! (`INCOMPATIBLE_VERSION`), `version` with `Admitted` at the next
//! protocol version, `VERSION + 1`, a newer driver. It serves until
//! `SIGTERM` or `SIGINT`. Linux only, as the admission socket is.

use std::process::ExitCode;

/// Exit status of a command-line or startup error.
const EXIT_ERROR: u8 = 2;

/// What every `Hello` is answered with.
#[derive(Debug, Clone, Copy)]
enum Mode {
    Refuse,
    Version,
}

const USAGE: &str = "usage: karyos-admission-stub --dir <dir> --mode refuse|version\n";

fn main() -> ExitCode {
    // R-CORE-33: `--versions` before anything else, touching no driver.
    if let Some(code) = karyos_tools::versions::intercept(std::env::args_os().skip(1)) {
        return code;
    }
    let mut dir = None;
    let mut mode = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match (arg.to_str(), args.next()) {
            (Some("--dir"), Some(value)) => dir = Some(std::path::PathBuf::from(value)),
            (Some("--mode"), Some(value)) => {
                mode = match value.to_str() {
                    Some("refuse") => Some(Mode::Refuse),
                    Some("version") => Some(Mode::Version),
                    _ => return fail(&"--mode is refuse or version"),
                };
            }
            _ => return fail(&USAGE.trim_end()),
        }
    }
    match (dir, mode) {
        (Some(dir), Some(mode)) => run(&dir, mode),
        _ => fail(&USAGE.trim_end()),
    }
}

#[cfg(not(target_os = "linux"))]
fn run(_dir: &std::path::Path, _mode: Mode) -> ExitCode {
    fail(&"the admission socket is Linux only")
}

#[cfg(target_os = "linux")]
fn run(dir: &std::path::Path, mode: Mode) -> ExitCode {
    use std::os::fd::{AsFd, OwnedFd};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use karyos_protocol::admission::{MAX_MESSAGE_LENGTH, Message, VERSION, refusal};
    use karyos_sys::ipc::{self, Recv};
    use signal_hook::consts::signal::{SIGINT, SIGTERM};

    /// How long an answered connection is kept, so the client reads the
    /// answer before the stub closes it; and how long a client may take
    /// to send its `Hello`.
    const LINGER: Duration = Duration::from_secs(1);

    let stop = Arc::new(AtomicBool::new(false));
    for signal in [SIGTERM, SIGINT] {
        if let Err(error) = signal_hook::flag::register(signal, Arc::clone(&stop)) {
            return fail(&format_args!("signal handler registration failed: {error}"));
        }
    }
    let answer = match mode {
        // As a driver of this core refuses: stating its version
        // (karyos#879).
        Mode::Refuse => match core::num::NonZeroU64::new(VERSION) {
            Some(version) => Message::incompatible_version(version),
            None => Message::Refused {
                fetch: 0,
                code: refusal::INCOMPATIBLE_VERSION,
            },
        },
        Mode::Version => match VERSION.checked_add(1) {
            Some(version) => Message::Admitted {
                instance: 1,
                version,
                client: 1,
                records: Vec::new(),
            },
            None => return fail(&"no protocol version after this one"),
        },
    };
    let mut encoded = [0u8; MAX_MESSAGE_LENGTH];
    let length = match answer.encode(&mut encoded) {
        Ok(length) => length,
        Err(error) => return fail(&format_args!("the answer does not encode: {error}")),
    };
    let Some(encoded) = encoded.get(..length) else {
        return fail(&"the answer does not fit");
    };
    let listener = match ipc::listen(dir, 16) {
        Ok(listener) => listener,
        Err(error) => return fail(&format_args!("listen on {}: {error}", dir.display())),
    };
    // Each connection: since when, and whether it was answered.
    let mut connections: Vec<(OwnedFd, Instant, bool)> = Vec::new();
    let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
    while !stop.load(Ordering::Relaxed) {
        match ipc::accept(listener.as_fd()) {
            Ok(Some(socket)) => connections.push((socket, Instant::now(), false)),
            Ok(None) => {}
            Err(error) => return fail(&format_args!("accept: {error}")),
        }
        for (socket, since, answered) in &mut connections {
            if *answered {
                continue;
            }
            match ipc::recv(socket.as_fd(), &mut buffer) {
                Ok(Recv::Message(received)) => {
                    let hello = buffer
                        .get(..received.len)
                        .map(Message::decode)
                        .is_some_and(|message| matches!(message, Ok(Message::Hello { .. })));
                    if hello {
                        let _ = ipc::send(socket.as_fd(), encoded, None);
                    }
                    // Anything but a `Hello` is not answered; the
                    // connection is closed with the others.
                    *answered = true;
                    *since = Instant::now();
                }
                Ok(Recv::WouldBlock) => {}
                Ok(Recv::PeerClosed) | Err(_) => *answered = true,
            }
        }
        connections.retain(|(_, since, _)| since.elapsed() < LINGER);
        std::thread::sleep(Duration::from_millis(1));
    }
    ExitCode::SUCCESS
}

/// Prints the error line and returns status 2.
fn fail(error: &dyn std::fmt::Display) -> ExitCode {
    use std::io::Write;

    let _ = writeln!(std::io::stderr(), "karyos-admission-stub: {error}");
    ExitCode::from(EXIT_ERROR)
}
