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
    worker: std::thread::JoinHandle<()>,
}

impl Request {
    /// Ends the program and everything it started, off the asking thread:
    /// a reaper kills the program's process group (so a wrapper's own
    /// children, which may hold its output open, end too), reaps the
    /// program and joins the I/O worker. Returns the reaper.
    fn end(self) -> Option<std::thread::JoinHandle<()>> {
        let Self {
            mut child, worker, ..
        } = self;
        std::thread::Builder::new()
            .name("karyosd-signer-reaper".to_owned())
            .spawn(move || {
                #[cfg(unix)]
                let _ = Command::new("kill")
                    .args(["-KILL", "--", &format!("-{}", child.id())])
                    .stderr(Stdio::null())
                    .status();
                let _ = child.kill();
                let _ = child.wait();
                let _ = worker.join();
            })
            .ok()
    }
}

/// A head signer that runs the operator's signing program.
pub struct CommandSigner {
    program: PathBuf,
    key_id: Digest,
    request: Option<Request>,
    /// The reaper of the last request ended: a new program starts only
    /// once it has finished, so at most one program, worker and reaper
    /// exist at a time.
    reaper: Option<std::thread::JoinHandle<()>>,
}

impl Drop for CommandSigner {
    /// The program of a request still in flight ends with the signer.
    fn drop(&mut self) {
        if let Some(request) = self.request.take() {
            self.retire(request);
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
            reaper: None,
        }
    }

    /// Starts the program for `bytes`: its input is written and its
    /// answer read on their own thread, never the asking one.
    /// Ends `request` through its reaper, kept until it finishes.
    fn retire(&mut self, request: Request) {
        self.reaper = request.end();
    }

    fn start(&mut self, bytes: Vec<u8>) {
        if self
            .reaper
            .as_ref()
            .is_some_and(|reaper| !reaper.is_finished())
        {
            // The last program is still being ended: no second one yet.
            return;
        }
        self.reaper = None;
        let mut command = Command::new(&self.program);
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        let Ok(mut child) = command
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
        if let Ok(worker) = started {
            self.request = Some(Request {
                bytes,
                since: Instant::now(),
                child,
                answer,
                worker,
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
    answer(stdout)
}

/// The signature a program's output states: read up to one byte past
/// [`MAX_ANSWER`], so an output longer than that is refused before it is
/// trimmed or parsed, never a prefix taken for the answer.
fn answer(output: impl Read) -> Option<[u8; SIGNATURE_LENGTH]> {
    let mut text = String::new();
    output
        .take(MAX_ANSWER.checked_add(1)?)
        .read_to_string(&mut text)
        .ok()?;
    if u64::try_from(text.len()).ok()? > MAX_ANSWER {
        return None;
    }
    signature(text.trim())
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
                self.retire(request);
            } else {
                match request.answer.try_recv() {
                    // An answer: it counts once the program has exited
                    // successfully, checked without blocking the asker.
                    Ok(Some(signature)) => match request.child.try_wait() {
                        Ok(Some(status)) if status.success() => {
                            self.retire(request);
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
                        _ => self.retire(request),
                    },
                    Ok(None) | Err(TryRecvError::Disconnected) => self.retire(request),
                    Err(TryRecvError::Empty) if request.since.elapsed() >= SIGN_TIMEOUT => {
                        self.retire(request);
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
        // The first program is ended off the asking thread, by its
        // reaper: `kill -0` soon finds no such process.
        let alive = || {
            Command::new("kill")
                .args(["-0", &first])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        };
        let start = Instant::now();
        while alive() && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!alive(), "the first program still runs");
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
    /// karyos#966 review P2: an answer longer than `MAX_ANSWER` is refused
    /// by its length, even when it starts with a valid signature.
    #[test]
    fn an_answer_past_the_limit_is_refused_by_length() {
        let valid = "ab".repeat(SIGNATURE_LENGTH);
        assert_eq!(
            answer(format!("{valid}\n").as_bytes()),
            Some([0xab; SIGNATURE_LENGTH])
        );
        let at_limit = format!("{valid}{}", " ".repeat(256 - valid.len()));
        assert_eq!(at_limit.len(), 256);
        assert_eq!(answer(at_limit.as_bytes()), Some([0xab; SIGNATURE_LENGTH]));
        let past = format!("{at_limit} ");
        assert_eq!(answer(past.as_bytes()), None);
    }
    /// karyos#966 review P2: a signer program whose own child keeps its
    /// output open is ended with its whole process group, off the asking
    /// thread, within a bound: the reaper finishes, no process of the group
    /// remains, and a new program can start.
    #[test]
    fn a_wrapper_whose_child_holds_the_output_is_ended_with_its_group() {
        let dir = dir("group");
        let pid = dir.join("pid");
        let program = script(
            &dir,
            "wrapper",
            &format!("echo $$ > {}\nsleep 60 &\nsleep 60", pid.display()),
        );
        let mut signer = CommandSigner::new(program, &[3; 32]);
        assert_eq!(signer.sign(&head()), Err(SignerUnavailable));
        let start = Instant::now();
        while !pid.exists() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(200));
        let group = std::fs::read_to_string(&pid).unwrap().trim().to_owned();
        // Another head replaces the request: the asking thread returns at
        // once, and the reaper ends the group.
        let asked = Instant::now();
        let other = ChainHead {
            counter: 4,
            ..head()
        };
        assert_eq!(signer.sign(&other), Err(SignerUnavailable));
        assert!(
            asked.elapsed() < Duration::from_secs(1),
            "the asker blocked"
        );
        let reaper = signer.reaper.take().unwrap();
        let start = Instant::now();
        while !reaper.is_finished() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(reaper.is_finished(), "the cleanup did not finish");
        reaper.join().unwrap();
        // No process of the group remains: `kill -0 -<group>` finds none.
        let any = Command::new("kill")
            .args(["-0", "--", &format!("-{group}")])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(!any, "a process of the group remains");
        drop(signer);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
