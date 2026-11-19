// SPDX-License-Identifier: Apache-2.0

//! The operator's head signer for `karyosd --archive` (quantstratum-docs:
//! karyos/SPEC.md §8.4, "Signed heads and custody"; karyos#966).
//!
//! The private archival key never resides on the Archive host. The Archive
//! asks a signer the operator runs, on another host or in a key service,
//! through a program the operator names with `--archive-signer`: the
//! program is run as `<program> sign`, is given the head's signed bytes as
//! lowercase hex and a newline on its standard input, and answers the
//! 64-byte Ed25519 signature as 128 hex digits on its standard output. A
//! program that reaches a remote signer (over SSH, or a key service's
//! client) is the operator's choice; this module only speaks to it.
//!
//! The agent asks from its control path, which also runs the recorders, so
//! the program never runs on the asking thread: each request runs on its
//! own thread, and the signer answers [`SignerUnavailable`] until the
//! signature is there. A request that takes longer than [`SIGN_TIMEOUT`]
//! is abandoned and asked again.
//!
//! The custody is [`Custody::Declared`]: a signature coming from another
//! host does not by itself prove custody separation.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use karyos_archive::integrity::Digest;
use karyos_archive::integrity::signing::{HeadSigner, SignerUnavailable};
use karyos_archive::integrity::trust::{
    ChainHead, Custody, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, key_id,
};

/// How long one signing request may take before it is asked again.
pub const SIGN_TIMEOUT: Duration = Duration::from_secs(60);

/// A request in flight.
struct Request {
    bytes: Vec<u8>,
    since: Instant,
    answer: Receiver<Option<[u8; SIGNATURE_LENGTH]>>,
}

/// A head signer that runs the operator's signing program.
pub struct CommandSigner {
    program: PathBuf,
    key_id: Digest,
    request: Option<Request>,
}

impl std::fmt::Debug for CommandSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandSigner")
            .field("program", &self.program)
            .finish_non_exhaustive()
    }
}

impl CommandSigner {
    /// A signer running `program`, which signs with the key whose public
    /// key is `public`.
    #[must_use]
    pub fn new(program: PathBuf, public: &[u8; PUBLIC_KEY_LENGTH]) -> Self {
        Self {
            program,
            key_id: key_id(public),
            request: None,
        }
    }

    /// Starts a request for `bytes` on its own thread.
    fn start(&mut self, bytes: Vec<u8>) {
        let (sender, answer) = mpsc::sync_channel(1);
        let program = self.program.clone();
        let input = hex(&bytes);
        let started = std::thread::Builder::new()
            .name("karyosd-signer".to_owned())
            .spawn(move || {
                let _ = sender.send(run(&program, &input));
            });
        if started.is_ok() {
            self.request = Some(Request {
                bytes,
                since: Instant::now(),
                answer,
            });
        }
    }
}

/// Runs `program sign` with `input` on its standard input; the signature
/// it prints, or `None`.
fn run(program: &PathBuf, input: &str) -> Option<[u8; SIGNATURE_LENGTH]> {
    let mut child = Command::new(program)
        .arg("sign")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    {
        let mut stdin = child.stdin.take()?;
        stdin.write_all(input.as_bytes()).ok()?;
        stdin.write_all(b"\n").ok()?;
    }
    let mut output = String::new();
    child.stdout.take()?.read_to_string(&mut output).ok()?;
    if !child.wait().ok()?.success() {
        return None;
    }
    signature(output.trim())
}

/// `bytes` as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The signature 128 hex digits state.
fn signature(text: &str) -> Option<[u8; SIGNATURE_LENGTH]> {
    let mut out = [0u8; SIGNATURE_LENGTH];
    if text.len() != SIGNATURE_LENGTH.checked_mul(2)? {
        return None;
    }
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

impl HeadSigner for CommandSigner {
    fn key_id(&self) -> Digest {
        self.key_id
    }

    fn custody(&self) -> Custody {
        Custody::Declared
    }

    fn sign(&mut self, head: &ChainHead) -> Result<[u8; SIGNATURE_LENGTH], SignerUnavailable> {
        let bytes = head.signed_bytes(self.custody());
        if let Some(request) = self
            .request
            .as_ref()
            .filter(|request| request.bytes == bytes)
        {
            match request.answer.try_recv() {
                Ok(Some(signature)) => {
                    self.request = None;
                    return Ok(signature);
                }
                Ok(None) | Err(TryRecvError::Disconnected) => self.request = None,
                Err(TryRecvError::Empty) if request.since.elapsed() >= SIGN_TIMEOUT => {
                    self.request = None;
                }
                Err(TryRecvError::Empty) => return Err(SignerUnavailable),
            }
        }
        // A request for another head is dropped: the agent asks for the
        // head it needs now.
        self.start(bytes);
        Err(SignerUnavailable)
    }
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests, as ADR-0007 allows"
    )]

    use super::*;

    fn head() -> ChainHead {
        ChainHead {
            archive_id: [7; 32],
            journal_id: 1,
            counter: 3,
            digest: [5; 32],
        }
    }

    /// A program that answers a fixed signature, after checking it was
    /// asked to sign the head's bytes.
    fn program(dir: &std::path::Path, expected: &str, answer: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("signer");
        let script = format!(
            "#!/bin/sh\n[ \"$1\" = sign ] || exit 2\nread input\n[ \"$input\" = \"{expected}\" ] || exit 3\necho {answer}\n"
        );
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("karyosd-signer-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ask(signer: &mut CommandSigner) -> Result<[u8; SIGNATURE_LENGTH], SignerUnavailable> {
        let start = Instant::now();
        loop {
            match signer.sign(&head()) {
                Err(SignerUnavailable) if start.elapsed() < Duration::from_secs(10) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                other => return other,
            }
        }
    }

    #[test]
    fn the_program_signs_the_heads_bytes_off_the_asking_thread() {
        let dir = dir("signs");
        let expected = hex(&head().signed_bytes(Custody::Declared));
        let answer = "ab".repeat(SIGNATURE_LENGTH);
        let mut signer = CommandSigner::new(program(&dir, &expected, &answer), &[3; 32]);
        // The first ask only starts the request.
        assert_eq!(signer.sign(&head()), Err(SignerUnavailable));
        assert_eq!(ask(&mut signer), Ok([0xab; SIGNATURE_LENGTH]));
        assert_eq!(signer.key_id(), key_id(&[3; 32]));
        assert_eq!(signer.custody(), Custody::Declared);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failing_or_malformed_answer_is_unavailable() {
        let dir = dir("fails");
        let mut signer = CommandSigner::new(program(&dir, "not these bytes", "00"), &[3; 32]);
        let _ = signer.sign(&head());
        std::thread::sleep(Duration::from_millis(300));
        // The failed request is dropped and asked again: still unavailable.
        assert_eq!(signer.sign(&head()), Err(SignerUnavailable));
        assert_eq!(signature("zz"), None);
        assert_eq!(signature(&"0".repeat(127)), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
