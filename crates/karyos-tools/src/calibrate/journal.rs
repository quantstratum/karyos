// SPDX-License-Identifier: Apache-2.0

//! `karyos-tools calibrate append --journal <dir>` (karyos#1137): appends
//! records to a calibration journal
//! (`karyos_archive::integrity::calibration_journal`), durable before it
//! returns, making the journal if it is absent. `karyosd
//! --archive-calibration-journal <dir>` reads it.
//!
//! The records are given as words after the options (18 words each), or,
//! with none, read from standard input: each line that starts with
//! `record` is one record of exactly 18 words, which is what `calibrate
//! phc` prints, so `karyos-tools calibrate phc | karyos-tools calibrate
//! append --journal <dir>` journals a calibration. A word is hexadecimal
//! with `0x`, or decimal. The batch is all or none (ADR-0110): a known
//! type that does not decode, or a `valid_from` not after the last of its
//! type and clock, is reported per record and nothing is appended; a
//! record already in the journal is reported "already present" and
//! skipped, so a retried batch never duplicates; a type this build does
//! not know is appended, for a newer reader.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use karyos_archive::disk::StdDisk;
use karyos_archive::integrity::calibration_journal::{Appended, CalibrationJournal, JournalError};
use karyos_trace::clocks::CALIBRATION_WORDS;

use super::EXIT_ERROR;

#[cfg(test)]
mod tests;

/// The usage text of `karyos-tools calibrate append --help`.
pub const HELP: &str = "\
karyos-tools calibrate append: append records to a calibration journal.

Usage: karyos-tools calibrate append --journal <dir> [<word>...]

The records are the words given (18 per record), or, with none, each
line of standard input that starts with `record`, one record of exactly
18 words per line (what `calibrate phc` prints). The batch is all or
none: a refused record (malformed, or a valid_from not after the last of
its type and clock) appends nothing; a record already present is
skipped. The journal directory is made if absent; the records are
committed before the command returns. karyosd reads the journal with
--archive-calibration-journal <dir>.
";

/// One word: hexadecimal with `0x`, or decimal.
fn word(text: &str) -> Result<u64, String> {
    let parsed = match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.map_err(|_| format!("{text} is not a record word"))
}

/// One record from exactly 18 words.
fn record(words: &[&str]) -> Result<[u64; CALIBRATION_WORDS], String> {
    if words.len() != CALIBRATION_WORDS {
        return Err(format!(
            "{} words: a record is {CALIBRATION_WORDS} words",
            words.len()
        ));
    }
    let mut record = [0u64; CALIBRATION_WORDS];
    for (slot, text) in record.iter_mut().zip(words) {
        *slot = word(text)?;
    }
    Ok(record)
}

/// The records of `words` given as arguments, 18 each.
///
/// # Errors
///
/// A message for a word that does not parse, or a count that is not a
/// nonzero multiple of 18.
pub fn records(words: &[String]) -> Result<Vec<[u64; CALIBRATION_WORDS]>, String> {
    if words.is_empty() || !words.len().is_multiple_of(CALIBRATION_WORDS) {
        return Err(format!(
            "{} words: records are {CALIBRATION_WORDS} words each",
            words.len()
        ));
    }
    words
        .chunks(CALIBRATION_WORDS)
        .map(|chunk| record(&chunk.iter().map(String::as_str).collect::<Vec<_>>()))
        .collect()
}

/// The records of `input`: each line that starts with `record` is one
/// record of exactly 18 words, never joined with another line.
///
/// # Errors
///
/// A message naming the line of a record that is short, long, marker
/// only or has a word that does not parse, or of a read failure; none at
/// all is an error too.
pub fn input_records(input: &mut dyn BufRead) -> Result<Vec<[u64; CALIBRATION_WORDS]>, String> {
    let mut records = Vec::new();
    for (index, line) in input.lines().enumerate() {
        let line = line.map_err(|error| format!("standard input: {error}"))?;
        let mut fields = line.split_whitespace();
        if fields.next() == Some("record") {
            let words: Vec<&str> = fields.collect();
            records.push(record(&words).map_err(|error| format!("line {}: {error}", index + 1))?);
        }
    }
    if records.is_empty() {
        return Err("no record line on standard input".to_owned());
    }
    Ok(records)
}

/// Makes `dir` and its missing ancestors, then syncs the parent of each
/// directory it made, outermost first, so the new entries are durable.
/// Returns the parents synced.
///
/// # Errors
///
/// The operating system's error.
pub fn create_dir_durable(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut missing = Vec::new();
    let mut at = Some(dir);
    while let Some(path) = at {
        if path.as_os_str().is_empty() || path.exists() {
            break;
        }
        missing.push(path.to_path_buf());
        at = path.parent();
    }
    std::fs::create_dir_all(dir)?;
    let mut synced = Vec::new();
    for made in missing.iter().rev() {
        let parent = match made.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };
        std::fs::File::open(&parent)?.sync_all()?;
        synced.push(parent);
    }
    Ok(synced)
}

/// Runs `karyos-tools calibrate append` with `args` (after `append`),
/// reading records from `input` when none are given.
pub fn run(
    args: impl Iterator<Item = std::ffi::OsString>,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let mut journal: Option<PathBuf> = None;
    let mut words = Vec::new();
    let mut args = args;
    while let Some(arg) = args.next() {
        let arg = arg.to_string_lossy().into_owned();
        match arg.as_str() {
            "-h" | "--help" => {
                let _ = out.write_all(HELP.as_bytes());
                return 0;
            }
            "--journal" => match args.next() {
                Some(value) => journal = Some(PathBuf::from(value)),
                None => {
                    let _ = writeln!(
                        err,
                        "karyos-tools calibrate append: --journal needs a value"
                    );
                    return EXIT_ERROR;
                }
            },
            _ if arg.starts_with("--") => {
                let _ = writeln!(err, "karyos-tools calibrate append: unknown option {arg}");
                return EXIT_ERROR;
            }
            _ => words.push(arg),
        }
    }
    let Some(journal) = journal else {
        let _ = writeln!(err, "karyos-tools calibrate append: --journal is required");
        return EXIT_ERROR;
    };
    let parsed = if words.is_empty() {
        input_records(input)
    } else {
        records(&words)
    };
    let records = match parsed {
        Ok(records) => records,
        Err(error) => {
            let _ = writeln!(err, "karyos-tools calibrate append: {error}");
            return EXIT_ERROR;
        }
    };
    if let Err(error) = create_dir_durable(&journal) {
        let _ = writeln!(
            err,
            "karyos-tools calibrate append: {}: {error}",
            journal.display()
        );
        return EXIT_ERROR;
    }
    let mut writer = match CalibrationJournal::open(StdDisk, &journal) {
        Ok(writer) => writer,
        Err(error) => {
            let _ = writeln!(
                err,
                "karyos-tools calibrate append: {}: {error}",
                journal.display()
            );
            return EXIT_ERROR;
        }
    };
    match writer.append_batch(&records) {
        Ok(outcomes) => {
            for (index, outcome) in outcomes.iter().enumerate() {
                let _ = match outcome {
                    Appended::At(at) => writeln!(out, "record {index}: appended at {at}"),
                    Appended::AlreadyPresent => writeln!(out, "record {index}: already present"),
                };
            }
        }
        Err(JournalError::Refused(refused)) => {
            for (index, refusal) in refused {
                let _ = writeln!(
                    err,
                    "karyos-tools calibrate append: record {index}: {refusal}"
                );
            }
            let _ = writeln!(err, "karyos-tools calibrate append: nothing appended");
            return EXIT_ERROR;
        }
        Err(error) => {
            let _ = writeln!(
                err,
                "karyos-tools calibrate append: {}: {error}",
                journal.display()
            );
            return EXIT_ERROR;
        }
    }
    0
}
