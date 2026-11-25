// SPDX-License-Identifier: Apache-2.0

//! `karyos-tools calibrate append --journal <dir>` (karyos#1137): appends
//! records to a calibration journal
//! (`karyos_archive::integrity::calibration_journal`), durable before it
//! returns, making the journal if it is absent. `karyosd
//! --archive-calibration-journal <dir>` reads it.
//!
//! The records are given as words after the options (18 words each), or,
//! with none, read from standard input: the words after `record` on each
//! line that starts with it, which is what `calibrate phc` prints, so
//! `karyos-tools calibrate phc | karyos-tools calibrate append --journal
//! <dir>` journals a calibration. A word is hexadecimal with `0x`, or
//! decimal. Every record is checked before any is appended: a known type
//! that does not decode refuses the whole run; a type this build does not
//! know is appended, for a newer reader.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use karyos_archive::disk::StdDisk;
use karyos_archive::integrity::calibration_journal::CalibrationJournal;
use karyos_trace::clocks::CALIBRATION_WORDS;
use karyos_trace::clocks::record::ClockRecord;

use super::EXIT_ERROR;

#[cfg(test)]
mod tests;

/// The usage text of `karyos-tools calibrate append --help`.
pub const HELP: &str = "\
karyos-tools calibrate append: append records to a calibration journal.

Usage: karyos-tools calibrate append --journal <dir> [<word>...]

The records are the words given (18 per record), or, with none, the
words after `record` on each line of standard input that starts with it
(what `calibrate phc` prints). The journal directory is made if absent;
each record is durable before the command returns. karyosd reads the
journal with --archive-calibration-journal <dir>.
";

/// One word: hexadecimal with `0x`, or decimal.
fn word(text: &str) -> Result<u64, String> {
    let parsed = match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.map_err(|_| format!("{text} is not a record word"))
}

/// The records of `words`, 18 each, checked.
///
/// # Errors
///
/// A message for a word that does not parse, a count that is not a
/// multiple of 18, none at all, or a known record type that does not
/// decode.
pub fn records(words: &[String]) -> Result<Vec<[u64; CALIBRATION_WORDS]>, String> {
    if words.is_empty() || !words.len().is_multiple_of(CALIBRATION_WORDS) {
        return Err(format!(
            "{} words: records are {CALIBRATION_WORDS} words each",
            words.len()
        ));
    }
    let mut out = Vec::with_capacity(words.len() / CALIBRATION_WORDS);
    for chunk in words.chunks(CALIBRATION_WORDS) {
        let mut record = [0u64; CALIBRATION_WORDS];
        for (slot, text) in record.iter_mut().zip(chunk) {
            *slot = word(text)?;
        }
        ClockRecord::decode(&record).map_err(|error| format!("record {}: {error}", out.len()))?;
        out.push(record);
    }
    Ok(out)
}

/// The words after `record` on each line of `input` that starts with it.
fn input_words(input: &mut dyn BufRead) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    for line in input.lines() {
        let line = line.map_err(|error| format!("standard input: {error}"))?;
        let mut fields = line.split_whitespace();
        if fields.next() == Some("record") {
            words.extend(fields.map(str::to_owned));
        }
    }
    Ok(words)
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
    if words.is_empty() {
        words = match input_words(input) {
            Ok(words) => words,
            Err(error) => {
                let _ = writeln!(err, "karyos-tools calibrate append: {error}");
                return EXIT_ERROR;
            }
        };
    }
    let records = match records(&words) {
        Ok(records) => records,
        Err(error) => {
            let _ = writeln!(err, "karyos-tools calibrate append: {error}");
            return EXIT_ERROR;
        }
    };
    if let Err(error) = std::fs::create_dir_all(&journal) {
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
    for record in &records {
        match writer.append(record) {
            Ok(at) => {
                let _ = writeln!(out, "appended at {at}");
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
    }
    0
}
