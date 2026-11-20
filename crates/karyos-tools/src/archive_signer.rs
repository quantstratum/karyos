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
//! Cleanup (karyos#1017) keeps ownership and identity:
//!
//! - **Ownership.** A request being ended is kept by the signer until its
//!   reaper runs: when the reaper thread cannot start, the request stays
//!   in the signer, which tries again on the next ask and starts no new
//!   program meanwhile. Its child and worker are never dropped unended.
//! - **Cancellable I/O.** The worker reads the program's output without
//!   blocking, polling it with a short timeout and a cancel flag, so a
//!   descendant that holds the output open outside the group cannot keep
//!   the worker, and so the reaper, alive: cancelled, the worker ends.
//! - **Identity.** The program is never reaped before its group is
//!   signalled: success is read with `waitid(WNOWAIT)`, which leaves it a
//!   zombie, and the reaper kills its group first and reaps it after. A
//!   group whose leader is unreaped cannot be reused, so the kill never
//!   reaches another group.
//!
//! The custody is [`Custody::Declared`]: a signature coming from another
//! host does not by itself prove custody separation.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// How long the worker waits for output before it looks at its cancel
/// flag again.
const READ_TICK: Duration = Duration::from_millis(10);

/// A request in flight: its program, which this request kills and reaps.
struct Request {
    bytes: Vec<u8>,
    since: Instant,
    child: Child,
    answer: Receiver<Option<[u8; SIGNATURE_LENGTH]>>,
    worker: std::thread::JoinHandle<()>,
    /// Set to stop the worker's I/O.
    cancel: Arc<AtomicBool>,
}

/// Ends `child` and everything it started, and joins `worker`: the group
/// is killed while its leader is still unreaped, then the leader is
/// reaped and the worker, cancelled, joined.
fn end(mut child: Child, worker: std::thread::JoinHandle<()>, cancel: &AtomicBool) {
    cancel.store(true, Ordering::Release);
    // The leader is not reaped before this: its group id is still its.
    let leader = rustix::process::Pid::from_child(&child);
    let _ = rustix::process::kill_process_group(leader, rustix::process::Signal::KILL);
    let _ = child.kill();
    let _ = child.wait();
    let _ = worker.join();
}

impl Request {
    /// Ends the program and everything it started, off the asking thread,
    /// on a reaper: [`end`]. Returns the reaper, or the request itself
    /// when no reaper thread could start, so it is never dropped unended
    /// (`None` only if the thread took it and still failed to report).
    fn end(self) -> Result<std::thread::JoinHandle<()>, Option<Self>> {
        let cancel = Arc::clone(&self.cancel);
        cancel.store(true, Ordering::Release);
        // The request is moved into the thread only once it exists.
        let slot = Arc::new(std::sync::Mutex::new(Some(self)));
        let taken = Arc::clone(&slot);
        let spawned = std::thread::Builder::new()
            .name("karyosd-signer-reaper".to_owned())
            .spawn(move || {
                let request = taken
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(request) = request {
                    end(request.child, request.worker, &request.cancel);
                }
            });
        match spawned {
            Ok(reaper) => Ok(reaper),
            // No thread ran, so the request is still in the slot.
            Err(_) => Err(slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()),
        }
    }

    /// Whether the program has exited successfully, read without reaping
    /// it (`waitid` with `WNOWAIT`): its group id stays its own until the
    /// reaper has signalled the group.
    fn succeeded(&self) -> Option<bool> {
        use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};
        let pid = Pid::from_child(&self.child);
        match waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Ok(Some(status)) => Some(status.exit_status() == Some(0) && status.exited()),
            Ok(None) => None,
            Err(_) => Some(false),
        }
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
    /// A request being ended whose reaper could not start yet: kept, and
    /// retried on the next ask (karyos#1017).
    retiring: Option<Request>,
}

impl Drop for CommandSigner {
    /// The program of a request still in flight ends with the signer; one
    /// no reaper could take is ended here, its worker cancelled first so
    /// the join is bounded.
    fn drop(&mut self) {
        if let Some(request) = self.request.take() {
            self.retire(request);
        }
        if let Some(request) = self.retiring.take() {
            end(request.child, request.worker, &request.cancel);
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
            retiring: None,
        }
    }

    /// Starts the program for `bytes`: its input is written and its
    /// answer read on their own thread, never the asking one.
    /// Ends `request` through its reaper, kept until it finishes; a
    /// request no reaper could take is kept to be retried.
    fn retire(&mut self, request: Request) {
        match request.end() {
            Ok(reaper) => self.reaper = Some(reaper),
            Err(kept) => self.retiring = kept,
        }
    }

    /// Retries ending a request whose reaper could not start.
    fn retry_retire(&mut self) {
        if self
            .reaper
            .as_ref()
            .is_some_and(|reaper| !reaper.is_finished())
        {
            return;
        }
        if let Some(request) = self.retiring.take() {
            self.retire(request);
        }
    }

    fn start(&mut self, bytes: Vec<u8>) {
        if self.retiring.is_some()
            || self
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
        // The output is read without blocking, so the worker can be
        // cancelled whoever holds the pipe open.
        let nonblocking = rustix::fs::fcntl_getfl(&stdout).and_then(|flags| {
            rustix::fs::fcntl_setfl(&stdout, flags | rustix::fs::OFlags::NONBLOCK)
        });
        let (sender, answer) = mpsc::sync_channel(1);
        let input = hex(&bytes);
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&cancel);
        let started = nonblocking.is_ok().then(|| {
            std::thread::Builder::new()
                .name("karyosd-signer".to_owned())
                .spawn(move || {
                    let _ = sender.send(exchange(stdin, stdout, &input, &stop));
                })
        });
        if let Some(Ok(worker)) = started {
            self.request = Some(Request {
                bytes,
                since: Instant::now(),
                child,
                answer,
                worker,
                cancel,
            });
        } else {
            // No worker holds the pipes: the group is ended here, its
            // leader reaped only after.
            let leader = rustix::process::Pid::from_child(&child);
            let _ = rustix::process::kill_process_group(leader, rustix::process::Signal::KILL);
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Writes `input` and a newline to the program, then reads its answer, at
/// most [`MAX_ANSWER`] bytes: the signature it states, or `None`. It ends
/// when the output closes, or once `cancel` is set, whoever holds the
/// output open.
fn exchange(
    mut stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
    input: &str,
    cancel: &AtomicBool,
) -> Option<[u8; SIGNATURE_LENGTH]> {
    stdin.write_all(input.as_bytes()).ok()?;
    stdin.write_all(b"\n").ok()?;
    drop(stdin);
    answer(Cancellable {
        output: stdout,
        cancel,
    })
}

/// A non-blocking output read as a blocking one until `cancel` is set:
/// then it reads as an error, so the reader ends.
struct Cancellable<'a> {
    output: std::process::ChildStdout,
    cancel: &'a AtomicBool,
}

impl Read for Cancellable<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.cancel.load(Ordering::Acquire) {
                // Not `Interrupted`, which a reader retries.
                return Err(std::io::Error::other("cancelled"));
            }
            match self.output.read(buf) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let mut fds = [rustix::event::PollFd::new(
                        &self.output,
                        rustix::event::PollFlags::IN,
                    )];
                    let tick = rustix::event::Timespec {
                        tv_sec: 0,
                        tv_nsec: READ_TICK.subsec_nanos().into(),
                    };
                    let _ = rustix::event::poll(&mut fds, Some(&tick));
                }
                other => return other,
            }
        }
    }
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
        self.retry_retire();
        if let Some(mut request) = self.request.take() {
            if request.bytes != bytes {
                // Another head: this request ends, killed and reaped,
                // before the new one starts.
                self.retire(request);
            } else {
                match request.answer.try_recv() {
                    // An answer: it counts once the program has exited
                    // successfully, checked without blocking the asker.
                    // Peeked, not reaped: the reaper signals the group
                    // before it reaps the leader (karyos#1017).
                    Ok(Some(signature)) => match request.succeeded() {
                        Some(true) => {
                            self.retire(request);
                            return Ok(signature);
                        }
                        None if request.since.elapsed() < SIGN_TIMEOUT => {
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
        clippy::panic,
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
        settle(&path);
        path
    }

    /// Waits until `path`, just written, can be executed (karyos#1063).
    /// A test thread that forks while another holds the file open for
    /// writing gives its child a copy of that descriptor until the child
    /// execs, and an exec of the file meanwhile fails with `ETXTBSY`. The
    /// probe runs the program with the argument `probe`, which every test
    /// program answers by exiting at once.
    fn settle(path: &std::path::Path) {
        let start = Instant::now();
        loop {
            match Command::new(path)
                .arg("probe")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(mut child) => {
                    let _ = child.wait();
                    return;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::ExecutableFileBusy
                        && start.elapsed() < Duration::from_secs(10) =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("{} does not run: {error}", path.display()),
            }
        }
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
        std::fs::write(
            &path,
            format!("#!/bin/sh\n[ \"$1\" = probe ] && exit 0\n{body}\n"),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        settle(&path);
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
    /// Waits for `reaper` to finish, at most ten seconds.
    fn finished(reaper: std::thread::JoinHandle<()>) {
        let start = Instant::now();
        while !reaper.is_finished() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(reaper.is_finished(), "the cleanup did not finish");
        reaper.join().unwrap();
    }

    /// A wrapper that signs `other`'s bytes at once and, for any other
    /// head, writes its pid to `pid` and runs `hold` holding its output.
    fn wrapper(
        dir: &std::path::Path,
        pid: &std::path::Path,
        other: &ChainHead,
        hold: &str,
    ) -> PathBuf {
        let expected = hex(&other.signed_bytes(Custody::Declared));
        let answer = "cd".repeat(SIGNATURE_LENGTH);
        script(
            dir,
            "wrapper",
            &format!(
                "read input\nif [ \"$input\" = \"{expected}\" ]; then echo {answer}; exit 0; fi\necho $$ > {}\n{hold}",
                pid.display()
            ),
        )
    }

    fn wait_for(path: &std::path::Path) -> String {
        let start = Instant::now();
        while !path.exists() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(200));
        std::fs::read_to_string(path).unwrap().trim().to_owned()
    }

    /// karyos#966 review P2, and karyos#1017's P3: a signer program whose
    /// own child keeps its output open is ended with its whole process
    /// group, off the asking thread, within a bound, and a replacement
    /// request then signs. Nothing here depends on the host reaping
    /// orphans: the test asserts the cleanup finished and the next request
    /// ran, not that no zombie of the group remains.
    #[test]
    fn a_wrapper_whose_child_holds_the_output_is_ended_with_its_group() {
        let dir = dir("group");
        let pid = dir.join("pid");
        let other = ChainHead {
            counter: 4,
            ..head()
        };
        let program = wrapper(&dir, &pid, &other, "sleep 60 &\nsleep 60");
        let mut signer = CommandSigner::new(program, &[3; 32]);
        assert_eq!(signer.sign(&head()), Err(SignerUnavailable));
        let _ = wait_for(&pid);
        // Another head replaces the request: the asking thread returns at
        // once, and the reaper ends the group.
        let asked = Instant::now();
        assert_eq!(signer.sign(&other), Err(SignerUnavailable));
        assert!(
            asked.elapsed() < Duration::from_secs(1),
            "the asker blocked"
        );
        finished(signer.reaper.take().unwrap());
        // The replacement starts and signs.
        let start = Instant::now();
        let signed = loop {
            match signer.sign(&other) {
                Err(SignerUnavailable) if start.elapsed() < Duration::from_secs(10) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                result => break result,
            }
        };
        assert_eq!(signed, Ok([0xcd; SIGNATURE_LENGTH]));
        drop(signer);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// karyos#1017 P2: a descendant in a session of its own, outside the
    /// signer's group, keeps the output open after the group is killed.
    /// The worker's read is cancelled, so the cleanup still finishes and a
    /// replacement request runs; retries are never blocked by the pipe.
    #[test]
    fn a_descendant_outside_the_group_cannot_block_the_cleanup() {
        let dir = dir("escaped");
        let pid = dir.join("pid");
        let escaped = dir.join("escaped");
        let other = ChainHead {
            counter: 4,
            ..head()
        };
        let hold = format!(
            "perl -e 'use POSIX; POSIX::setsid(); open(my $f, \">\", \"{}\"); print $f \"$$\\n\"; close $f; exec \"sleep\", \"60\"' &\nsleep 60",
            escaped.display()
        );
        let program = wrapper(&dir, &pid, &other, &hold);
        let mut signer = CommandSigner::new(program, &[3; 32]);
        assert_eq!(signer.sign(&head()), Err(SignerUnavailable));
        let _ = wait_for(&pid);
        let escaped_pid = wait_for(&escaped);
        assert_eq!(signer.sign(&other), Err(SignerUnavailable));
        finished(signer.reaper.take().unwrap());
        let start = Instant::now();
        let signed = loop {
            match signer.sign(&other) {
                Err(SignerUnavailable) if start.elapsed() < Duration::from_secs(10) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                result => break result,
            }
        };
        assert_eq!(signed, Ok([0xcd; SIGNATURE_LENGTH]));
        drop(signer);
        // The escaped descendant is this test's to end.
        let _ = Command::new("kill")
            .args(["-KILL", &escaped_pid])
            .stderr(Stdio::null())
            .status();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// karyos#1017 P2: success is read without reaping the program, so its
    /// group id cannot be reused before the reaper signals the group.
    #[test]
    fn success_is_read_without_reaping_the_program() {
        let dir = dir("unreaped");
        let program = script(&dir, "quick", "exit 0");
        let mut command = Command::new(&program);
        let child = command.stdout(Stdio::null()).spawn().unwrap();
        let (_sender, answer) = mpsc::sync_channel(1);
        let request = Request {
            bytes: Vec::new(),
            since: Instant::now(),
            child,
            answer,
            worker: std::thread::spawn(|| {}),
            cancel: Arc::new(AtomicBool::new(false)),
        };
        let start = Instant::now();
        let mut seen = None;
        while seen.is_none() && start.elapsed() < Duration::from_secs(10) {
            seen = request.succeeded();
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(seen, Some(true));
        // Still unreaped: peeking again reads the same exit.
        assert_eq!(request.succeeded(), Some(true));
        let Request {
            mut child, worker, ..
        } = request;
        assert!(child.wait().unwrap().success());
        worker.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
