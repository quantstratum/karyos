// SPDX-License-Identifier: Apache-2.0

//! `karyos-replay start` and `stop` (`quantstratum-docs:
//! karyos/design/archive-host.md`, H6): ask a running Archive to replay a
//! recording into a stream, or to stop a replay, over its control streams
//! (SPEC.md section 8.2).
//!
//! `start` sends a `Replay` and prints the answer: the replay's id and the
//! target's stream and session, where a reader finds it. The Archive holds
//! the replay until the target's first reader joins (H2b), up to its
//! attach deadline, so a reader that subscribes after the answer reads it
//! from its first position. `stop` sends a `StopReplay`.
//!
//! The exchange ([`request`]) runs over any facade client: the binary
//! connects to the driver in `--live`'s directory (Linux), and tests use
//! an in-process one. Exit status: 0 on success, [`EXIT_ERROR`] for any
//! error, the Archive's refusal included.

use std::ffi::OsString;
use std::io::Write;
use std::time::{Duration, Instant};

use karyos_archive::client::connection::{ArchiveConnection, ControlStreams};
use karyos_archive::client::{ControlRequests, ControlResponses};
use karyos_archive::control::{self, ControlMessage, ControlResponse, ReplayRate, ResponseCode};
use karyos_archive::server::{MAX_ANSWER, MAX_REQUEST, replay_session_id};
use karyos_client::{Client, Connection};

use crate::args::{ArgsError, LiveArchive, parse_live};

/// The exit status of an error: as `karyos-catalog`'s, unlike `diff`'s.
pub const EXIT_ERROR: u8 = 2;

/// How long a command waits by default for the driver and for the
/// Archive's answer.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// `karyos-replay start`'s arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartArgs {
    /// The Archive.
    pub live: LiveArchive,
    /// The recording.
    pub recording: u64,
    /// The first position replayed.
    pub from: u64,
    /// Bytes replayed; `u64::MAX` to the recording's end.
    pub length: u64,
    /// The target stream.
    pub stream: i32,
    /// The target channel.
    pub channel: String,
    /// How long to wait for the driver and the answer.
    pub timeout: Duration,
}

/// `karyos-replay stop`'s arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopArgs {
    /// The Archive.
    pub live: LiveArchive,
    /// The replay.
    pub replay: u64,
    /// How long to wait for the driver and the answer.
    pub timeout: Duration,
}

/// The options each command reads, and their values, as given.
type Options = Vec<(&'static str, String)>;

/// Reads `--name value` or `--name=value` pairs among `known`; `None` for
/// `-h` or `--help`.
fn options(
    args: impl IntoIterator<Item = OsString>,
    known: &[&'static str],
) -> Result<Option<Options>, ArgsError> {
    let mut found = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let text = arg
            .to_str()
            .ok_or_else(|| ArgsError::UnknownOption(arg.to_string_lossy().into_owned()))?;
        if text == "-h" || text == "--help" {
            return Ok(None);
        }
        let (name, inline) = match text.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value.to_owned())),
            _ => (text, None),
        };
        let option = known
            .iter()
            .copied()
            .find(|option| *option == name)
            .ok_or_else(|| ArgsError::UnknownOption(text.to_owned()))?;
        let value = match inline {
            Some(value) => value,
            None => args
                .next()
                .and_then(|value| value.into_string().ok())
                .ok_or(ArgsError::MissingValue(option))?,
        };
        found.push((option, value));
    }
    Ok(Some(found))
}

/// The last value of `option`, parsed.
fn value<V: std::str::FromStr>(
    found: &Options,
    option: &'static str,
) -> Result<Option<V>, ArgsError> {
    found
        .iter()
        .rev()
        .find(|(name, _)| *name == option)
        .map(|(_, value)| {
            value.parse().map_err(|_| ArgsError::InvalidValue {
                option,
                value: value.clone(),
            })
        })
        .transpose()
}

fn live(found: &Options) -> Result<LiveArchive, ArgsError> {
    let value = found
        .iter()
        .rev()
        .find(|(name, _)| *name == "--live")
        .ok_or(ArgsError::Missing("--live"))?;
    parse_live(&value.1)
}

fn timeout(found: &Options) -> Result<Duration, ArgsError> {
    Ok(value::<u64>(found, "--timeout-ms")?.map_or(DEFAULT_TIMEOUT, Duration::from_millis))
}

/// Parses `karyos-replay start`'s arguments; `None` for help.
///
/// # Errors
///
/// [`ArgsError`] for an unknown option, a missing or invalid value, or a
/// recording id of 0.
pub fn parse_start(
    args: impl IntoIterator<Item = OsString>,
) -> Result<Option<StartArgs>, ArgsError> {
    let Some(found) = options(
        args,
        &[
            "--live",
            "--recording",
            "--from",
            "--length",
            "--to-stream",
            "--channel",
            "--timeout-ms",
        ],
    )?
    else {
        return Ok(None);
    };
    let recording =
        value::<u64>(&found, "--recording")?.ok_or(ArgsError::Missing("--recording"))?;
    if recording == 0 {
        return Err(ArgsError::InvalidValue {
            option: "--recording",
            value: "0".to_owned(),
        });
    }
    Ok(Some(StartArgs {
        live: live(&found)?,
        recording,
        from: value(&found, "--from")?.unwrap_or(0),
        length: value(&found, "--length")?.unwrap_or(u64::MAX),
        stream: value(&found, "--to-stream")?.ok_or(ArgsError::Missing("--to-stream"))?,
        channel: value(&found, "--channel")?.unwrap_or_else(|| "karyos:ipc".to_owned()),
        timeout: timeout(&found)?,
    }))
}

/// Parses `karyos-replay stop`'s arguments; `None` for help.
///
/// # Errors
///
/// [`ArgsError`] for an unknown option, a missing or invalid value, or a
/// replay id of 0.
pub fn parse_stop(args: impl IntoIterator<Item = OsString>) -> Result<Option<StopArgs>, ArgsError> {
    let Some(found) = options(args, &["--live", "--replay", "--timeout-ms"])? else {
        return Ok(None);
    };
    let replay = value::<u64>(&found, "--replay")?.ok_or(ArgsError::Missing("--replay"))?;
    if replay == 0 {
        return Err(ArgsError::InvalidValue {
            option: "--replay",
            value: "0".to_owned(),
        });
    }
    Ok(Some(StopArgs {
        live: live(&found)?,
        replay,
        timeout: timeout(&found)?,
    }))
}

/// Why a command failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveError {
    /// The driver or the control streams could not be reached.
    Connect(String),
    /// The request was not accepted within the timeout.
    NotSent,
    /// No answer came within the timeout.
    NoAnswer,
    /// The Archive refused the request.
    Refused {
        /// Its code.
        code: ResponseCode,
        /// Its message.
        message: String,
    },
}

impl std::fmt::Display for LiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(why) => write!(f, "cannot reach the Archive: {why}"),
            Self::NotSent => f.write_str("the request was not taken within the timeout"),
            Self::NoAnswer => f.write_str("no answer within the timeout"),
            Self::Refused { code, message } => write!(f, "refused ({code:?}): {message}"),
        }
    }
}

/// A correlation id of this process: its id in the high 32 bits, as the
/// Archive's clients do, so answers to other requesters are told apart.
fn correlation(sequence: u32) -> u64 {
    (u64::from(std::process::id()) << 32) | u64::from(sequence)
}

/// Sends `message` over `streams` through `client` and waits for the
/// answer to its `correlation_id`: the answer's id on `Ok`. Answers to
/// other requests are skipped.
///
/// # Errors
///
/// [`LiveError`].
pub fn request<C: Connection>(
    client: &mut Client<C>,
    streams: ControlStreams,
    message: &ControlMessage<'_>,
    correlation_id: u64,
    timeout: Duration,
) -> Result<u64, LiveError>
where
    karyos_archive::client::connection::Requests<C::Terms>: ControlRequests,
    karyos_archive::client::connection::Responses<C::Terms>: ControlResponses,
{
    let (mut requests, mut responses) = ArchiveConnection::open(client, streams)
        .map_err(|error| LiveError::Connect(error.to_string()))?
        .into_transports();
    let mut out = vec![0u8; MAX_REQUEST];
    let length = message
        .encode(&mut out)
        .map_err(|error| LiveError::Connect(format!("encode: {error}")))?;
    out.truncate(length);
    let start = Instant::now();
    while !requests.send(&out) {
        if start.elapsed() >= timeout {
            return Err(LiveError::NotSent);
        }
        let _ = client.poll();
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut answer = vec![0u8; MAX_ANSWER];
    loop {
        let _ = client.poll();
        while let Some(length) = responses.next(&mut answer) {
            let Some(bytes) = answer.get(..length) else {
                continue;
            };
            if let Ok(ControlMessage::ControlResponse(ControlResponse {
                correlation_id: id,
                id: answer_id,
                code,
                message,
            })) = ControlMessage::decode(bytes)
                && id == correlation_id
            {
                return if code == ResponseCode::Ok {
                    Ok(answer_id)
                } else {
                    Err(LiveError::Refused {
                        code,
                        message: message.to_owned(),
                    })
                };
            }
        }
        if start.elapsed() >= timeout {
            return Err(LiveError::NoAnswer);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Starts the replay `args` asks for through `client`: the replay's id and
/// its target's session id.
///
/// # Errors
///
/// As [`request`].
pub fn start<C: Connection>(
    client: &mut Client<C>,
    args: &StartArgs,
) -> Result<(u64, i32), LiveError>
where
    karyos_archive::client::connection::Requests<C::Terms>: ControlRequests,
    karyos_archive::client::connection::Responses<C::Terms>: ControlResponses,
{
    let correlation_id = correlation(1);
    let replay = request(
        client,
        ControlStreams::new(args.live.requests, args.live.responses),
        &ControlMessage::Replay(control::Replay {
            correlation_id,
            recording_id: args.recording,
            position: args.from,
            length: args.length,
            rate: ReplayRate::Full,
            target_stream_id: args.stream,
            target_channel: &args.channel,
        }),
        correlation_id,
        args.timeout,
    )?;
    Ok((replay, replay_session_id(replay)))
}

/// Stops the replay `args` names through `client`.
///
/// # Errors
///
/// As [`request`].
pub fn stop<C: Connection>(client: &mut Client<C>, args: &StopArgs) -> Result<(), LiveError>
where
    karyos_archive::client::connection::Requests<C::Terms>: ControlRequests,
    karyos_archive::client::connection::Responses<C::Terms>: ControlResponses,
{
    let correlation_id = correlation(2);
    request(
        client,
        ControlStreams::new(args.live.requests, args.live.responses),
        &ControlMessage::StopReplay(control::StopReplay {
            correlation_id,
            replay_id: args.replay,
        }),
        correlation_id,
        args.timeout,
    )
    .map(drop)
}

/// The usage of `command`, `karyos-replay start` or `stop`.
fn help(command: &str) -> String {
    if command.ends_with("stop") {
        format!(
            "Usage: {command} --live DIR=REQ,RESP --replay ID [--timeout-ms N]\n\n\
             Stops a replay of the Archive whose control streams are REQ and RESP on the\n\
             driver in DIR. Exit status 0, or {EXIT_ERROR} on any error.\n"
        )
    } else {
        format!(
            "Usage: {command} --live DIR=REQ,RESP --recording ID --to-stream S\n\
             \x20      [--from POS] [--length BYTES] [--channel URI] [--timeout-ms N]\n\n\
             Asks the Archive whose control streams are REQ and RESP on the driver in DIR\n\
             to replay recording ID from POS (0) for BYTES (to its end) onto stream S\n\
             (channel karyos:ipc). Prints `replay=ID stream=S session=N`: subscribe to\n\
             stream S, session N, to read it. The Archive holds the replay until its first\n\
             reader joins, up to its attach deadline. Exit status 0, or {EXIT_ERROR} on any\n\
             error.\n"
        )
    }
}

/// Runs `command` (`karyos-replay start` or `stop`, as `which` says) with
/// `args`, writing to `stdout` and `stderr`; returns the exit status.
pub fn run(
    command: &str,
    which: Command,
    args: impl IntoIterator<Item = OsString>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let program = command.split(' ').next().unwrap_or(command);
    let fail = |stderr: &mut dyn Write, error: &dyn std::fmt::Display| {
        let _ = writeln!(stderr, "{program}: {error}");
        EXIT_ERROR
    };
    match which {
        Command::Start => match parse_start(args) {
            Ok(None) => {
                let _ = stdout.write_all(help(command).as_bytes());
                0
            }
            Err(error) => fail(stderr, &format!("{error} ({command} --help for the usage)")),
            Ok(Some(args)) => match connect(&args.live, args.timeout) {
                Err(error) => fail(stderr, &error),
                Ok(mut client) => match start(&mut client, &args) {
                    Ok((replay, session)) => {
                        let _ = writeln!(
                            stdout,
                            "replay={replay} stream={} session={session}",
                            args.stream
                        );
                        0
                    }
                    Err(error) => fail(stderr, &error),
                },
            },
        },
        Command::Stop => match parse_stop(args) {
            Ok(None) => {
                let _ = stdout.write_all(help(command).as_bytes());
                0
            }
            Err(error) => fail(stderr, &format!("{error} ({command} --help for the usage)")),
            Ok(Some(args)) => match connect(&args.live, args.timeout) {
                Err(error) => fail(stderr, &error),
                Ok(mut client) => match stop(&mut client, &args) {
                    Ok(()) => {
                        let _ = writeln!(stdout, "stopped replay={}", args.replay);
                        0
                    }
                    Err(error) => fail(stderr, &error),
                },
            },
        },
    }
}

/// Which command [`run`] runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `start`.
    Start,
    /// `stop`.
    Stop,
}

/// A client of the driver in `live`'s directory (Linux).
#[cfg(target_os = "linux")]
fn connect(
    live: &LiveArchive,
    timeout: Duration,
) -> Result<Client<karyos_client::ipc::RemoteClient>, LiveError> {
    let context = karyos_client::Context::builder()
        .dir(&live.dir)
        .timeout(timeout)
        .build()
        .map_err(|error| LiveError::Connect(error.to_string()))?;
    Client::connect(context).map_err(|error| LiveError::Connect(error.to_string()))
}

/// A client of another process's driver needs Linux.
#[cfg(not(target_os = "linux"))]
fn connect(
    _live: &LiveArchive,
    _timeout: Duration,
) -> Result<Client<karyos_client::ClientConductor>, LiveError> {
    Err(LiveError::Connect(
        "connecting to another process's driver needs Linux".to_owned(),
    ))
}

#[cfg(test)]
mod tests;
