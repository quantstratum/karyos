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
//! signature is there. One request is in flight at a time: a request for
//! another head, or one past [`SIGN_TIMEOUT`], ends the program (killed and
//! reaped) before a new one starts, and the program's answer is read up to
//! [`MAX_ANSWER`] bytes.
//!
//! The custody is [`Custody::Declared`]: a signature coming from another
//! host does not by itself prove custody separation.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use karyos_archive::integrity::Digest;
use karyos_archive::integrity::signing::{HeadSigner, SignerUnavailable};
use karyos_archive::integrity::trust::{
    ChainHead, Custody, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, key_id,
};

/// How long one signing request may take before it is asked again.
pub const SIGN_TIMEOUT: Duration = Duration::from_secs(60);

/// The most of a program's answer read: 128 hex digits and a line end,
/// with room for a carriage return and spaces.
pub const MAX_ANSWER: u64 = 256;

/// A request in flight: its program, which this request kills and reaps.
struct Request {
    bytes: Vec<u8>,
    since: Instant,
    child: Child,
    answer: Receiver<Option<[u8; SIGNATURE_LENGTH]>>,
}

impl Request {
    /// Ends the program, if it still runs, and reaps it.
    fn end(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A head signer that runs the operator's signing program.
pub struct CommandSigner {
    program: PathBuf,
    key_id: Digest,
    request: Option<Request>,
}

impl Drop for CommandSigner {
    /// The program of a request still in flight ends with the signer.
    fn drop(&mut self) {
        if let Some(request) = self.request.take() {
            request.end();
        }
    }
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

    /// Starts the program for `bytes`: its input is written and its
    /// answer read on their own thread, never the asking one.
    fn start(&mut self, bytes: Vec<u8>) {
        let Ok(mut child) = Command::new(&self.program)
            .arg("sign")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            return;
        };
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return;
        };
        let (sender, answer) = mpsc::sync_channel(1);
        let input = hex(&bytes);
        let started = std::thread::Builder::new()
            .name("karyosd-signer".to_owned())
            .spawn(move || {
                let _ = sender.send(exchange(stdin, stdout, &input));
            });
        if started.is_ok() {
            self.request = Some(Request {
                bytes,
                since: Instant::now(),
                child,
                answer,
            });
        } else {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Writes `input` and a newline to the program, then reads its answer, at
/// most [`MAX_ANSWER`] bytes: the signature it states, or `None`. It ends
/// when the program closes its output, exits, or is killed.
fn exchange(
    mut stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
    input: &str,
) -> Option<[u8; SIGNATURE_LENGTH]> {
    stdin.write_all(input.as_bytes()).ok()?;
    stdin.write_all(b"\n").ok()?;
    drop(stdin);
    let mut output = String::new();
    stdout.take(MAX_ANSWER).read_to_string(&mut output).ok()?;
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
        if let Some(mut request) = self.request.take() {
            if request.bytes != bytes {
                // Another head: this request ends, killed and reaped,
                // before the new one starts.
                request.end();
            } else {
                match request.answer.try_recv() {
                    // An answer: it counts once the program has exited
                    // successfully, checked without blocking the asker.
                    Ok(Some(signature)) => match request.child.try_wait() {
                        Ok(Some(status)) if status.success() => {
                            request.end();
                            return Ok(signature);
                        }
                        Ok(None) if request.since.elapsed() < SIGN_TIMEOUT => {
                            // Not exited yet: keep the answer for the next
                            // ask by putting it back.
                            let (sender, answer) = mpsc::sync_channel(1);
                            let _ = sender.send(Some(signature));
                            request.answer = answer;
                            self.request = Some(request);
                            return Err(SignerUnavailable);
                        }
                        _ => request.end(),
                    },
                    Ok(None) | Err(TryRecvError::Disconnected) => request.end(),
                    Err(TryRecvError::Empty) if request.since.elapsed() >= SIGN_TIMEOUT => {
                        request.end();
                    }
                    Err(TryRecvError::Empty) => {
                        self.request = Some(request);
                        return Err(SignerUnavailable);
                    }
                }
            }
        }
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
    /// A program from `script`'s body, run as `sh`.
    fn script(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// karyos#966 review P2: a request for another head ends the program
    /// still running for the first, killed and reaped, before the next.
    #[test]
    fn a_request_for_another_head_ends_the_running_program() {
        let dir = dir("replaced");
        let pid = dir.join("pid");
        let program = script(
            &dir,
            "slow",
            &format!("echo $$ > {}\nexec sleep 30", pid.display()),
        );
        let mut signer = CommandSigner::new(program, &[3; 32]);
        assert_eq!(signer.sign(&head()), Err(SignerUnavailable));
        let start = Instant::now();
        while !pid.exists() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(100));
        let first = std::fs::read_to_string(&pid).unwrap().trim().to_owned();
        let other = ChainHead {
            counter: 4,
            ..head()
        };
        assert_eq!(signer.sign(&other), Err(SignerUnavailable));
        // The first program is gone: `kill -0` finds no such process.
        let alive = Command::new("kill")
            .args(["-0", &first])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(!alive, "the first program still runs");
        drop(signer);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// karyos#966 review P2: an answer is read up to `MAX_ANSWER` bytes; a
    /// program that prints more is unavailable, not read without bound.
    #[test]
    fn an_oversized_answer_is_not_a_signature() {
        let dir = dir("oversized");
        let program = script(
            &dir,
            "loud",
            "read input\nhead -c 100000 /dev/zero | tr '\\0' a\necho",
        );
        let mut signer = CommandSigner::new(program, &[3; 32]);
        let _ = signer.sign(&head());
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            assert_eq!(signer.sign(&head()), Err(SignerUnavailable));
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(signer);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
