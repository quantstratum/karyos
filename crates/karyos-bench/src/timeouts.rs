// SPDX-License-Identifier: Apache-2.0

//! The measured inputs of the Cluster's election-timeout defaults
//! (ADR-0039: "choose election-timeout defaults per tested deployment
//! profile from simulated faults and measured process pauses and network
//! tails"; ADR-0105, decision 5): a host's process pauses and the
//! round-trip tail between two hosts, each report labelled with the host's
//! load while it ran, since a pause or a tail measured under load is that
//! load's number, not the host's.
//!
//! - **Pauses** ([`pause`]): a thread sleeps `tick` again and again for the
//!   run, and each wake's overshoot past `tick` is a sample: what the
//!   scheduler, the host's load and any stall add to a timer, which is what
//!   a node's election and heartbeat timers see.
//! - **Round trips** ([`echo`], [`rtt`]): UDP datagrams of a fixed size
//!   sent every `interval` to an echo on the other host; each answer's
//!   round trip is a sample, and a datagram without answer within a second
//!   is lost and counted, never a sample.
//! - **Load** ([`load_average`]): the one-minute load average, sampled once
//!   a second through the run: its least, mean and most go in the report.
//!
//! Every report is one JSON line ([`Report::json`]), so a run on several
//! hosts concatenates into one file the timeout record cites.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::stats::quantile;

/// A sample set's tail, in microseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tail {
    /// Samples.
    pub count: u64,
    /// The median.
    pub p50_us: u32,
    /// The 99th percentile.
    pub p99_us: u32,
    /// The 99.9th percentile.
    pub p999_us: u32,
    /// The largest.
    pub max_us: u32,
}

impl Tail {
    /// The tail of `samples`, in microseconds; all zero for none.
    #[must_use]
    pub fn of(samples: &[u32]) -> Self {
        Self {
            count: u64::try_from(samples.len()).unwrap_or(u64::MAX),
            p50_us: quantile(samples, 1, 2).unwrap_or(0),
            p99_us: quantile(samples, 99, 100).unwrap_or(0),
            p999_us: quantile(samples, 999, 1000).unwrap_or(0),
            max_us: samples.iter().copied().max().unwrap_or(0),
        }
    }
}

/// The host's one-minute load through a run.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Load {
    /// Samples taken.
    pub samples: u32,
    /// The least.
    pub min: f64,
    /// The mean.
    pub mean: f64,
    /// The most.
    pub max: f64,
}

impl Load {
    fn of(samples: &[f64]) -> Self {
        if samples.is_empty() {
            return Self::default();
        }
        let sum: f64 = samples.iter().sum();
        let count = u32::try_from(samples.len()).unwrap_or(u32::MAX);
        Self {
            samples: count,
            min: samples.iter().copied().fold(f64::INFINITY, f64::min),
            mean: sum / f64::from(count),
            max: samples.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        }
    }
}

/// One probe's report.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// `"pause"` or `"rtt"`.
    pub probe: &'static str,
    /// The host it ran on.
    pub host: String,
    /// The other host, for a round trip.
    pub peer: Option<String>,
    /// The timer tick, or the interval between datagrams, in microseconds.
    pub period_us: u64,
    /// The tail of its samples.
    pub tail: Tail,
    /// Datagrams without answer (a round trip's).
    pub lost: u64,
    /// The host's load while it ran.
    pub load: Load,
}

impl Report {
    /// The report as one JSON line.
    #[must_use]
    pub fn json(&self) -> String {
        format!(
            "{{\"probe\":\"{}\",\"host\":\"{}\",\"peer\":{},\"period_us\":{},\"count\":{},\"p50_us\":{},\"p99_us\":{},\"p999_us\":{},\"max_us\":{},\"lost\":{},\"load1_samples\":{},\"load1_min\":{:.2},\"load1_mean\":{:.2},\"load1_max\":{:.2}}}",
            self.probe,
            escape(&self.host),
            self.peer
                .as_deref()
                .map_or_else(|| "null".to_owned(), |peer| format!("\"{}\"", escape(peer))),
            self.period_us,
            self.tail.count,
            self.tail.p50_us,
            self.tail.p99_us,
            self.tail.p999_us,
            self.tail.max_us,
            self.lost,
            self.load.samples,
            self.load.min,
            self.load.mean,
            self.load.max,
        )
    }
}

fn escape(text: &str) -> String {
    text.chars()
        .filter(|c| *c != '"' && *c != '\\' && !c.is_control())
        .collect()
}

/// The host's one-minute load average: `/proc/loadavg` on Linux, `sysctl
/// vm.loadavg` on macOS; `None` where neither answers.
#[must_use]
pub fn load_average() -> Option<f64> {
    if let Ok(text) = std::fs::read_to_string("/proc/loadavg") {
        return parse_proc_loadavg(&text);
    }
    let output = std::process::Command::new("sysctl")
        .args(["-n", "vm.loadavg"])
        .output()
        .ok()?;
    parse_sysctl_loadavg(&String::from_utf8_lossy(&output.stdout))
}

/// The first field of `/proc/loadavg`.
#[must_use]
pub fn parse_proc_loadavg(text: &str) -> Option<f64> {
    text.split_whitespace().next()?.parse().ok()
}

/// The first number of `sysctl -n vm.loadavg`'s `{ 1.23 4.56 7.89 }`.
#[must_use]
pub fn parse_sysctl_loadavg(text: &str) -> Option<f64> {
    text.trim()
        .trim_start_matches('{')
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// The host's name.
#[must_use]
pub fn host() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// A microsecond count of `duration`, saturating.
fn micros(duration: Duration) -> u32 {
    u32::try_from(duration.as_micros()).unwrap_or(u32::MAX)
}

/// Sleeps `tick` again and again for `run`; each wake's overshoot past
/// `tick` is a sample, and the load is sampled once a second.
#[must_use]
pub fn pause(run: Duration, tick: Duration) -> Report {
    let mut samples = Vec::new();
    let mut loads = Vec::new();
    let start = Instant::now();
    let mut next_load = start;
    while start.elapsed() < run {
        if Instant::now() >= next_load {
            loads.extend(load_average());
            next_load += Duration::from_secs(1);
        }
        let before = Instant::now();
        std::thread::sleep(tick);
        samples.push(micros(before.elapsed().saturating_sub(tick)));
    }
    Report {
        probe: "pause",
        host: host(),
        peer: None,
        period_us: u64::try_from(tick.as_micros()).unwrap_or(u64::MAX),
        tail: Tail::of(&samples),
        lost: 0,
        load: Load::of(&loads),
    }
}

/// Answers every datagram on `bind` with itself, for `run`.
///
/// # Errors
///
/// The socket's errors.
pub fn echo(bind: SocketAddr, run: Duration) -> io::Result<u64> {
    let socket = UdpSocket::bind(bind)?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut buf = [0u8; 1500];
    let mut answered = 0u64;
    let start = Instant::now();
    while start.elapsed() < run {
        match socket.recv_from(&mut buf) {
            Ok((length, from)) => {
                let _ = socket.send_to(buf.get(..length).unwrap_or(&[]), from)?;
                answered += 1;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(answered)
}

/// The payload of datagram `sequence`: the sequence, then padding to
/// `size` bytes.
fn datagram(sequence: u64, size: usize) -> Vec<u8> {
    let mut bytes = sequence.to_le_bytes().to_vec();
    bytes.resize(size.max(8), 0);
    bytes
}

/// Sends `count` datagrams of `size` bytes to the echo at `to`, one every
/// `interval`, and takes each answer's round trip; one without answer
/// within a second is lost.
///
/// # Errors
///
/// The socket's errors.
pub fn rtt(to: SocketAddr, count: u64, interval: Duration, size: usize) -> io::Result<Report> {
    let bind: SocketAddr = if to.is_ipv4() {
        "0.0.0.0:0".parse().map_err(io::Error::other)?
    } else {
        "[::]:0".parse().map_err(io::Error::other)?
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(to)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut samples = Vec::new();
    let mut loads = Vec::new();
    let mut lost = 0u64;
    let mut buf = [0u8; 1500];
    let mut next_load = Instant::now();
    for sequence in 0..count {
        if Instant::now() >= next_load {
            loads.extend(load_average());
            next_load += Duration::from_secs(1);
        }
        let sent = Instant::now();
        let _ = socket.send(&datagram(sequence, size))?;
        // An answer to an earlier datagram, arriving late, is skipped.
        loop {
            match socket.recv(&mut buf) {
                Ok(length) if length >= 8 => {
                    let mut seq = [0u8; 8];
                    seq.copy_from_slice(buf.get(..8).unwrap_or(&[0; 8]));
                    if u64::from_le_bytes(seq) == sequence {
                        samples.push(micros(sent.elapsed()));
                        break;
                    }
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    lost += 1;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        if let Some(rest) = interval.checked_sub(sent.elapsed()) {
            std::thread::sleep(rest);
        }
    }
    Ok(Report {
        probe: "rtt",
        host: host(),
        peer: Some(to.to_string()),
        period_us: u64::try_from(interval.as_micros()).unwrap_or(u64::MAX),
        tail: Tail::of(&samples),
        lost,
        load: Load::of(&loads),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tail_is_read_from_its_samples() {
        let samples: Vec<u32> = (1..=1000).collect();
        let tail = Tail::of(&samples);
        assert_eq!(
            (
                tail.count,
                tail.p50_us,
                tail.p99_us,
                tail.p999_us,
                tail.max_us
            ),
            (1000, 500, 990, 999, 1000)
        );
        assert_eq!(Tail::of(&[]), Tail::default());
    }

    #[test]
    fn the_load_average_parses_on_both_systems() {
        assert_eq!(
            parse_proc_loadavg("1.25 0.80 0.50 2/300 4242\n"),
            Some(1.25)
        );
        assert_eq!(parse_sysctl_loadavg("{ 3.10 2.00 1.00 }\n"), Some(3.1));
        assert_eq!(parse_proc_loadavg(""), None);
        let load = Load::of(&[1.0, 3.0]);
        assert_eq!((load.samples, load.min, load.max), (2, 1.0, 3.0));
        assert!((load.mean - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_pause_probe_reports_its_tick_and_its_load() {
        let report = pause(Duration::from_millis(200), Duration::from_millis(5));
        assert_eq!(report.probe, "pause");
        assert_eq!(report.period_us, 5_000);
        assert!(report.tail.count >= 10, "{report:?}");
        let line = report.json();
        assert!(
            line.starts_with("{\"probe\":\"pause\",\"host\":\""),
            "{line}"
        );
        assert!(line.contains("\"peer\":null"), "{line}");
    }

    #[test]
    fn a_round_trip_probe_measures_against_a_local_echo() {
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);
        let server = std::thread::spawn(move || echo(address, Duration::from_secs(2)));
        std::thread::sleep(Duration::from_millis(100));
        let report = rtt(address, 50, Duration::from_millis(2), 64).unwrap();
        assert_eq!(report.lost, 0, "{report:?}");
        assert_eq!(report.tail.count, 50);
        assert!(report.json().contains(&format!("\"peer\":\"{address}\"")));
        assert_eq!(server.join().unwrap().unwrap(), 50);
    }
}
