// SPDX-License-Identifier: Apache-2.0

//! `karyos-tiering`: offline tiering of an Archive directory no `karyosd`
//! holds (quantstratum-docs: karyos/adr/0104-tiering-whole-segments.md;
//! karyos#1113).
//!
//! ```text
//! karyos-tiering offload|restore|verify --dir <archive> --recording <id>
//!     --location <hex>
//!     --endpoint <https url> --bucket <name> --region <region> [--path-style]
//!     --roots <pem file> --credentials <file> [--object-lock]
//!     [--timeout-ms <ms>] [--max-object <bytes>]
//!     [--min-copies <n>] [--limit <segments>] [--accept-downgrade-break]
//! ```
//!
//! - `offload` moves the recording's segments from its start, oldest
//!   first, to object storage; `restore` brings them back from the one just
//!   below the start downward; `verify` checks every remote object and
//!   downgrades a missing or corrupt copy.
//! - The directory's locks are taken without waiting: a running `karyosd`
//!   makes the run refuse, changing nothing.
//! - Configuration comes only from these flags and the credentials from
//!   the file `--credentials` names (its first line the access key id, its
//!   second the secret), never from the environment.
//! - `--location` must be the location the Archive records for its own
//!   copies; the object store's location in the copy catalog is derived
//!   from its endpoint and bucket ([`store_location`]), so another bucket
//!   is never taken for the one the copies were recorded at;
//!   copy catalog.
//! - The first tiering commit of a directory makes it unreadable by builds
//!   before ADR-0104; it needs `--accept-downgrade-break`.
//!
//! Exit status: 0 done, 1 refused or failed, 2 a command-line error.

use std::io::Write;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::Duration;

use karyos_archive::integrity::Digest;
use karyos_archive::integrity::copies::ImmutabilityBackend;
use karyos_archive::integrity::tiering::Tiering;
use karyos_archive::integrity::tiering_offline::{
    Offline, OfflineError, OffloadOptions, Stopped, hex,
};
use karyos_archive::segment::StdDisk;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use crate::{S3Config, S3Store};

/// Exit status of a refusal or failure.
pub const EXIT_REFUSED: i32 = 1;
/// Exit status of a command-line error.
pub const EXIT_USAGE: i32 = 2;

/// The usage text.
pub const USAGE: &str = "usage: karyos-tiering offload|restore|verify --dir <archive> --recording <id> \
--location <hex> --endpoint <https url> --bucket <name> --region <region> \
[--path-style] --roots <pem file> --credentials <file> [--object-lock] [--timeout-ms <ms>] \
[--max-object <bytes>] [--min-copies <n>] [--limit <segments>] [--accept-downgrade-break]\n";

/// What to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Offload segments.
    Offload,
    /// Restore segments.
    Restore,
    /// Verify the remote objects.
    Verify,
}

/// The parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// The command.
    pub command: Command,
    /// The Archive directory.
    pub dir: PathBuf,
    /// The recording.
    pub recording: u64,
    /// This Archive's location.
    pub location: Digest,
    /// The endpoint.
    pub endpoint: String,
    /// The bucket.
    pub bucket: String,
    /// The region.
    pub region: String,
    /// Path-style URLs.
    pub path_style: bool,
    /// The roots' PEM file.
    pub roots: PathBuf,
    /// The credentials file.
    pub credentials: PathBuf,
    /// Object lock on.
    pub object_lock: bool,
    /// One request's time limit.
    pub timeout: Duration,
    /// The largest object read back.
    pub max_object: usize,
    /// `min_copies` when no policy applies.
    pub min_copies: Option<NonZeroU32>,
    /// The most segments to move.
    pub limit: Option<u64>,
    /// The downgrade break accepted.
    pub accept_downgrade_break: bool,
}

/// A 32-byte location from 64 hex digits.
fn location(text: &str) -> Option<Digest> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// Parses the command line (without the program name).
///
/// # Errors
///
/// What is wrong with it.
pub fn parse(args: &[String]) -> Result<Args, String> {
    let mut args = args.iter();
    let command = match args.next().map(String::as_str) {
        Some("offload") => Command::Offload,
        Some("restore") => Command::Restore,
        Some("verify") => Command::Verify,
        Some(other) => return Err(format!("unknown command {other}")),
        None => return Err("a command is required".to_owned()),
    };
    let mut values: std::collections::BTreeMap<&str, String> = std::collections::BTreeMap::new();
    let (mut path_style, mut object_lock, mut accept) = (false, false, false);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--path-style" => path_style = true,
            "--object-lock" => object_lock = true,
            "--accept-downgrade-break" => accept = true,
            name @ ("--dir" | "--recording" | "--location" | "--endpoint" | "--bucket"
            | "--region" | "--roots" | "--credentials" | "--timeout-ms"
            | "--max-object" | "--min-copies" | "--limit") => {
                let value = args.next().ok_or_else(|| format!("{name} needs a value"))?;
                if values.insert(name, value.clone()).is_some() {
                    return Err(format!("{name} given twice"));
                }
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    let mut take = |name: &str| {
        values
            .remove(name)
            .ok_or_else(|| format!("{name} is required"))
    };
    let number = |name: &str, text: &str| {
        text.parse::<u64>()
            .map_err(|_| format!("{name}: not a number: {text}"))
    };
    let dir = PathBuf::from(take("--dir")?);
    let recording = number("--recording", &take("--recording")?)?;
    let location_of = |name: &str, text: String| {
        location(&text).ok_or_else(|| format!("{name}: 64 hex digits expected"))
    };
    let local = location_of("--location", take("--location")?)?;
    let endpoint = take("--endpoint")?;
    let bucket = take("--bucket")?;
    let region = take("--region")?;
    let roots = PathBuf::from(take("--roots")?);
    let credentials = PathBuf::from(take("--credentials")?);
    let timeout = match values.remove("--timeout-ms") {
        Some(text) => Duration::from_millis(number("--timeout-ms", &text)?),
        None => Duration::from_secs(30),
    };
    let max_object = match values.remove("--max-object") {
        Some(text) => usize::try_from(number("--max-object", &text)?)
            .map_err(|_| "--max-object: too large".to_owned())?,
        None => 256 << 20,
    };
    let min_copies = values
        .remove("--min-copies")
        .map(|text| {
            number("--min-copies", &text)
                .ok()
                .and_then(|n| u32::try_from(n).ok())
                .and_then(NonZeroU32::new)
                .ok_or_else(|| format!("--min-copies: a positive count expected: {text}"))
        })
        .transpose()?;
    let limit = values
        .remove("--limit")
        .map(|text| number("--limit", &text))
        .transpose()?;
    Ok(Args {
        command,
        dir,
        recording,
        location: local,
        endpoint,
        bucket,
        region,
        path_style,
        roots,
        credentials,
        object_lock,
        timeout,
        max_object,
        min_copies,
        limit,
        accept_downgrade_break: accept,
    })
}

/// The object store's location in the copy catalog: the SHA-256 of
/// `s3`, its endpoint and its bucket, each on its own line. Derived, never
/// given, so verifying against another bucket finds no copy recorded there
/// and refuses instead of downgrading healthy copies (#1207 review).
#[must_use]
pub fn store_location(endpoint: &str, bucket: &str) -> Digest {
    use graviola::hashing::{Hash, Sha256};
    let identity = format!("s3\n{}\n{bucket}", endpoint.trim_end_matches('/'));
    let mut out = [0u8; 32];
    out.copy_from_slice(Sha256::hash(identity.as_bytes()).as_ref());
    out
}

/// The access key id and the secret from a credentials file: its first two
/// non-empty lines.
///
/// # Errors
///
/// The file cannot be read, or it holds fewer than two lines.
pub fn credentials(path: &Path) -> Result<(String, String), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("--credentials {}: {error}", path.display()))?;
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    match (lines.next(), lines.next()) {
        (Some(key), Some(secret)) => Ok((key.to_owned(), secret.to_owned())),
        _ => Err(format!(
            "--credentials {}: the access key id and the secret, one per line, are required",
            path.display()
        )),
    }
}

/// The store `args` configure.
///
/// # Errors
///
/// The roots, the credentials or the store refused.
pub fn store(args: &Args) -> Result<S3Store, String> {
    let roots = CertificateDer::pem_file_iter(&args.roots)
        .and_then(|roots| roots.collect::<Result<Vec<_>, _>>())
        .map_err(|error| format!("--roots {}: {error}", args.roots.display()))?;
    if roots.is_empty() {
        return Err(format!("--roots {}: no certificate", args.roots.display()));
    }
    let (access_key, secret_key) = credentials(&args.credentials)?;
    S3Store::new(S3Config {
        endpoint: args.endpoint.clone(),
        path_style: args.path_style,
        bucket: args.bucket.clone(),
        region: args.region.clone(),
        access_key,
        secret_key,
        roots,
        object_lock: args.object_lock,
        timeout: args.timeout,
        max_object: args.max_object,
    })
    .map_err(|error| error.to_string())
}

fn backend() -> Box<dyn ImmutabilityBackend> {
    #[cfg(target_os = "linux")]
    {
        Box::new(karyos_archive::integrity::copies::ImmutableAttribute)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Box::new(karyos_archive::integrity::copies::NoImmutability)
    }
}

fn stopped(stopped: &Stopped) -> String {
    match stopped {
        Stopped::NoneLeft => "no finished segment left: the segment being written stays".to_owned(),
        Stopped::Limit => "the limit was reached".to_owned(),
        Stopped::NotEligible { base, why } => {
            format!("segment {base} skipped: not eligible: {why}")
        }
        Stopped::LockNotEnforced { base, object } => format!(
            "segment {base} skipped: object {object} does not enforce the retention deadline under object lock"
        ),
        Stopped::BelowMinCopies {
            base,
            verified,
            required,
        } => format!(
            "segment {base} skipped: {verified} verified copies would be left, {required} required"
        ),
        _ => "stopped".to_owned(),
    }
}

/// Runs `args` against the Archive and the object store, writing its report
/// to `out`: the exit status.
pub fn run_with<O: karyos_archive::integrity::tiering::ObjectStore>(
    args: &Args,
    store: &mut O,
    immutability: Box<dyn ImmutabilityBackend>,
    out: &mut dyn Write,
) -> i32 {
    match execute(args, store, immutability, out) {
        Ok(code) => code,
        Err(error) => {
            let _ = writeln!(out, "karyos-tiering: refused: {error}");
            EXIT_REFUSED
        }
    }
}

fn execute<O: karyos_archive::integrity::tiering::ObjectStore>(
    args: &Args,
    store: &mut O,
    immutability: Box<dyn ImmutabilityBackend>,
    out: &mut dyn Write,
) -> Result<i32, OfflineError> {
    let mut offline = Offline::open(StdDisk, &args.dir, immutability)?;
    offline.check_location(&args.location)?;
    let tiering = Tiering {
        local: args.location,
        remote: store_location(&args.endpoint, &args.bucket),
    };
    match args.command {
        Command::Offload => {
            if !offline.journal().tiered() && args.accept_downgrade_break {
                let _ = writeln!(
                    out,
                    "note: this directory becomes unreadable by builds before ADR-0104 (seal kinds 9 and 10)"
                );
            }
            let report = offline.offload(
                &tiering,
                args.recording,
                store,
                &OffloadOptions {
                    min_copies: args.min_copies,
                    accept_downgrade_break: args.accept_downgrade_break,
                    limit: args.limit,
                },
            )?;
            for record in &report.offloaded {
                let _ = writeln!(
                    out,
                    "offloaded recording {} [{}, {}) record {} index sha256 {}",
                    record.subject,
                    record.start,
                    record.end,
                    record.counter,
                    hex(&record.content)
                );
            }
            let _ = writeln!(out, "{}", stopped(&report.stopped));
            Ok(match report.stopped {
                Stopped::NoneLeft | Stopped::Limit => 0,
                _ => EXIT_REFUSED,
            })
        }
        Command::Restore => {
            let restored = offline.restore(&tiering, args.recording, store, args.limit)?;
            for record in &restored {
                let _ = writeln!(
                    out,
                    "restored recording {} [{}, {}) record {}",
                    record.subject, record.start, record.end, record.counter
                );
            }
            if restored.is_empty() {
                let _ = writeln!(out, "nothing is offloaded below the start");
            }
            Ok(0)
        }
        Command::Verify => {
            let reports = offline.verify(&tiering, args.recording, store)?;
            let mut bad = false;
            for report in &reports {
                bad |= report.state
                    != karyos_archive::integrity::tiering_offline::ObjectState::Verified;
                let _ = writeln!(
                    out,
                    "object {} recording {} [{}, {}) {}",
                    report.object,
                    report.recording,
                    report.start,
                    report.end,
                    report.state.name()
                );
            }
            Ok(if bad { EXIT_REFUSED } else { 0 })
        }
    }
}

/// Runs the command line `args` (without the program name): the exit
/// status.
pub fn run(args: &[String], out: &mut dyn Write) -> i32 {
    let args = match parse(args) {
        Ok(args) => args,
        Err(error) => {
            let _ = writeln!(out, "karyos-tiering: {error}\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    let mut store = match store(&args) {
        Ok(store) => store,
        Err(error) => {
            let _ = writeln!(out, "karyos-tiering: refused: {error}");
            return EXIT_REFUSED;
        }
    };
    run_with(&args, &mut store, backend(), out)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "tests, as ADR-0007 allows"
    )]

    use super::*;

    fn temp(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "karyos-tiering-{name}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn line(extra: &[&str]) -> Vec<String> {
        let mut args: Vec<String> = [
            "offload",
            "--dir",
            "/archive",
            "--recording",
            "3",
            "--location",
            &"0a".repeat(32),
            "--endpoint",
            "https://localhost:9000",
            "--bucket",
            "archive",
            "--region",
            "test-1",
            "--roots",
            "/roots.pem",
            "--credentials",
            "/credentials",
        ]
        .iter()
        .map(|arg| (*arg).to_owned())
        .collect();
        args.extend(extra.iter().map(|arg| (*arg).to_owned()));
        args
    }

    #[test]
    fn the_command_line_is_parsed_from_flags_only() {
        let args = parse(&line(&[
            "--object-lock",
            "--min-copies",
            "2",
            "--accept-downgrade-break",
        ]))
        .unwrap();
        assert_eq!(args.command, Command::Offload);
        assert_eq!(args.recording, 3);
        assert_eq!(args.location, [10; 32]);
        // The store's location is derived from its identity.
        assert_eq!(
            store_location("https://localhost:9000/", "archive"),
            store_location("https://localhost:9000", "archive")
        );
        assert_ne!(
            store_location("https://localhost:9000", "archive"),
            store_location("https://localhost:9000", "other")
        );
        assert!(args.object_lock && args.accept_downgrade_break && !args.path_style);
        assert_eq!(args.min_copies, NonZeroU32::new(2));
        assert_eq!(args.timeout, Duration::from_secs(30));
        for (bad, why) in [
            (line(&["--min-copies", "0"]), "--min-copies"),
            (line(&["--bogus"]), "unknown flag"),
            (line(&["--recording", "4"]), "given twice"),
        ] {
            assert!(parse(&bad).unwrap_err().contains(why), "{why}");
        }
        assert!(
            parse(&line(&["--remote-location", "00"]))
                .unwrap_err()
                .contains("unknown flag")
        );
        let missing: Vec<String> = line(&[])
            .into_iter()
            .take_while(|arg| arg != "--credentials")
            .collect();
        assert!(
            parse(&missing)
                .unwrap_err()
                .contains("--credentials is required")
        );
        assert!(
            parse(&["purge".to_owned()])
                .unwrap_err()
                .contains("unknown command")
        );
    }

    #[test]
    fn credentials_come_from_their_file_and_a_short_one_is_refused() {
        let dir = temp("credentials");
        let file = dir.join("credentials");
        std::fs::write(&file, "AKIDEXAMPLE\n\nsecret\n").unwrap();
        assert_eq!(
            credentials(&file).unwrap(),
            ("AKIDEXAMPLE".to_owned(), "secret".to_owned())
        );
        std::fs::write(&file, "AKIDEXAMPLE\n").unwrap();
        assert!(credentials(&file).unwrap_err().contains("one per line"));
        assert!(credentials(&dir.join("absent")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_directory_a_running_archive_holds_is_refused_and_unchanged() {
        let dir = temp("live");
        // The running Archive's lock, held by this handle.
        let held = karyos_archive::integrity::journal::IntegrityJournal::open(StdDisk, &dir)
            .unwrap()
            .journal;
        let mut before: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        before.sort();
        let refused = Offline::open(
            StdDisk,
            &dir,
            Box::new(karyos_archive::integrity::copies::NoImmutability),
        )
        .unwrap_err();
        assert!(matches!(refused, OfflineError::Live), "{refused:?}");
        let mut after: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        after.sort();
        assert_eq!(before, after);
        drop(held);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_roots_or_credentials_file_is_a_clear_refusal() {
        let mut out = Vec::new();
        let code = run(&line(&[]), &mut out);
        assert_eq!(code, EXIT_REFUSED);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("--roots /roots.pem"), "{text}");
        let mut out = Vec::new();
        assert_eq!(run(&["offload".to_owned()], &mut out), EXIT_USAGE);
    }
}
