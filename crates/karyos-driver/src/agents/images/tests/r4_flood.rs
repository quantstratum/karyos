// SPDX-License-Identifier: Apache-2.0

//! H10 R4 evidence for the `encrypted` class (wire-threat-model-manifest.md
//! sections 6.1 and 7; ADR-0114): the test-level equivalent of the R4
//! load, since the bench harness has no `encrypted` profile. A real
//! encrypted publication and subscription over loopback carry valid W1
//! traffic (`L` = 32, one message per append) at R2's two rates (100 000
//! and 1 000 000 messages/s) for a fixed time in wall-clock time, while
//! datagrams forged under a wrong key (the genuine context, an invalid
//! tag) are sent at 10% or 100% of the valid rate from up to
//! [`FORGERS`] other threads, each over a real UDP socket that shares the publisher's address and port
//! (a duplicate of its descriptor: the source a spoofing attacker
//! names), to the receiver's bound endpoint. They reach the receiver
//! through its polled transport, as an attacker's datagrams would. Each
//! run states the allocations of each agent's duties, the percentiles of
//! the receiver's complete intake interval (its duty cycle: the socket
//! read, the forged datagrams verified and refused, the valid ones
//! delivered), what was delivered and in which order, the forged
//! datagrams sent, received and dropped by UDP, the rejection counters
//! and the state the flood left. A run that does not sustain its load is
//! refused: at least [`MIN_LOAD_PERCENT`] of the scheduled valid and
//! forged datagrams sent, at most [`MAX_DROP_PERCENT`] of the forged
//! ones lost before the receiver read them, a schedule lag within
//! [`MAX_LAG_NS`] and [`MIN_SAMPLES_PER_SECOND`] intake samples per
//! second. Ignored:
//! run explicitly in release (`cargo test --release -p karyos-driver
//! --lib r4_ -- --ignored --nocapture`); each run prints its report, and
//! writes it to `r4-<rate>-<p>.txt` in the directory `KARYOS_R4_OUT` names, when
//! set.

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use karyos_io::sockets::ops::{RouteAddr, SendResult, SocketOps};

use karyos_protocol::protection::aes_gcm_siv::{Domain, EncRejection};
use karyos_sys::alloc_count::count_allocations;
use karyos_sys::log_buffer::{AppendOptions, AppendOutcome, PollOutcome, Role};

use super::*;
use crate::wire_enc::{
    ChannelKeys, DEFAULT_ENC_VERIFY_SLOTS, EncSealer, EncVerifyConfig, MAX_SEALED,
};

/// Verifier threads of the receiver's pool (ADR-0126) by default;
/// `KARYOS_R4_VERIFIERS` overrides it, 0 running every open on the
/// receiver's own thread.
const VERIFIERS: u16 = 3;

/// The receiver's verifier pool of a run: [`VERIFIERS`] threads and
/// [`DEFAULT_ENC_VERIFY_SLOTS`] slots, or `KARYOS_R4_VERIFIERS` and
/// `KARYOS_R4_SLOTS`.
fn r4_pool() -> EncVerifyConfig {
    let read = |name: &str, default: u16| {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    };
    EncVerifyConfig {
        verifiers: read("KARYOS_R4_VERIFIERS", VERIFIERS),
        slots: read("KARYOS_R4_SLOTS", DEFAULT_ENC_VERIFY_SLOTS),
    }
}

/// R2's lower valid rate (manifest 6.1), messages/s.
const RATE_LOW: u64 = 100_000;
/// R2's higher valid rate (manifest 6.1), messages/s.
const RATE_HIGH: u64 = 1_000_000;
/// Seconds each run lasts.
const SECONDS: u64 = 10;
/// Distinct forged datagrams, sent in a cycle.
const POOL: u64 = 4_096;
/// Bytes added to the forged plaintext: the forged datagrams take a
/// length the valid ones do not, so the receiver's intake counts them
/// as it reads them.
const FORGED_PAD: usize = 3;
/// Forged datagrams per send call at most.
const SEND_BATCH: usize = 32;
/// Threads sending the flood, each on its own duplicate of the
/// publisher's socket and its share of the schedule: one loopback sender
/// alone tops out near 450 000 datagrams/s on xaskar.
const FORGERS: u64 = 4;
/// Forged datagrams per second one sending thread is given at most.
const PER_FORGER: u64 = 300_000;
/// The share of the forged datagrams sent that UDP may lose before the
/// receiver reads them, or the run is refused as underloaded.
const MAX_DROP_PERCENT: u64 = 5;
/// Receiver duties timed at most.
const MAX_SAMPLES: usize = 1 << 24;
/// The share of the scheduled valid and forged datagrams a run must
/// send, or it is refused as underloaded.
const MIN_LOAD_PERCENT: u64 = 95;
/// The longest the valid load may fall behind its schedule: 10 ms, 1 000
/// messages at [`RATE_LOW`], 10 000 at [`RATE_HIGH`].
const MAX_LAG_NS: u64 = 10_000_000;
/// Intake intervals a run must time per second, at least (one per 1 ms on
/// average).
const MIN_SAMPLES_PER_SECOND: u64 = 1_000;

/// Nanoseconds the valid side's thread spent per phase: appends,
/// conductors, the sender duty, the control plane and subscriber.
#[derive(Debug, Default)]
struct Phases([u64; 4]);

impl Phases {
    /// Adds the time since `from` to phase `at`; returns now.
    fn lap(&mut self, at: usize, from: Instant) -> Instant {
        let now = Instant::now();
        self.0[at] += u64::try_from(now.duration_since(from).as_nanos()).unwrap();
        now
    }
}

/// The `q` quantile of sorted `samples`.
fn quantile(samples: &[u64], q: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "an index into a sample vector"
    )]
    let at = ((samples.len() - 1) as f64 * q).round() as usize;
    samples[at]
}

fn percentiles(label: &str, samples: &mut [u64], report: &mut String) {
    samples.sort_unstable();
    let _ = writeln!(
        report,
        "{label}: n={} p50={}ns p90={}ns p99={}ns p99.9={}ns p99.99={}ns max={}ns",
        samples.len(),
        quantile(samples, 0.5),
        quantile(samples, 0.9),
        quantile(samples, 0.99),
        quantile(samples, 0.999),
        quantile(samples, 0.9999),
        samples.last().copied().unwrap_or(0),
    );
}

/// What a run carried: valid messages appended, forged datagrams sent and
/// received, the largest schedule lag of the valid load (the flood's
/// is reported: its shortfall is the forged load rule) and the intake
/// samples timed.
#[derive(Debug, Clone, Copy)]
struct Load {
    appended: u64,
    forged_sent: u64,
    forged_received: u64,
    late_ns: u64,
    samples: usize,
}

/// Whether a run at `rate` valid messages/s and `invalid_percent` sustained
/// its load: at least [`MIN_LOAD_PERCENT`] of the scheduled valid and
/// forged datagrams, at most [`MAX_DROP_PERCENT`] of the forged ones sent
/// lost by UDP, a schedule lag within [`MAX_LAG_NS`] and enough intake
/// samples.
fn sustained(rate: u64, invalid_percent: u64, load: Load) -> Result<(), String> {
    let Load {
        appended,
        forged_sent,
        forged_received,
        late_ns,
        samples,
    } = load;
    let valid_target = rate * SECONDS;
    let forged_target = valid_target * invalid_percent / 100;
    if appended * 100 < valid_target * MIN_LOAD_PERCENT {
        return Err(format!("underloaded: {appended} valid of {valid_target}"));
    }
    if forged_sent * 100 < forged_target * MIN_LOAD_PERCENT {
        return Err(format!(
            "underloaded: {forged_sent} forged sent of {forged_target}"
        ));
    }
    if forged_received > forged_sent {
        return Err(format!(
            "{forged_received} forged received of {forged_sent} sent"
        ));
    }
    let drops = forged_sent - forged_received;
    if drops * 100 > forged_sent * MAX_DROP_PERCENT {
        return Err(format!(
            "underloaded: {drops} of {forged_sent} forged dropped by UDP"
        ));
    }
    if late_ns > MAX_LAG_NS {
        return Err(format!("schedule lag {late_ns}ns over {MAX_LAG_NS}ns"));
    }
    if u64::try_from(samples).unwrap_or(u64::MAX) < MIN_SAMPLES_PER_SECOND * SECONDS {
        return Err(format!("{samples} intake samples"));
    }
    Ok(())
}

/// One R4 run at `rate` valid messages/s and `invalid_percent` of it
/// forged; returns the report and asserts the H10 properties.
#[allow(clippy::too_many_lines, reason = "one measured run, read top down")]
fn r4(rate: u64, invalid_percent: u64) -> String {
    let verify = r4_pool();
    let (mut rig, b) =
        crate::agents::roles::receive_enc::with_enc_verifiers(verify, true, encrypted_rig);
    assert_eq!(
        rig.agents.receiver.role.enc_verifiers(),
        (verify.verifiers > 0).then_some(usize::from(verify.verifiers)),
        "the pool runs"
    );
    crate::wire_enc::record_seals();
    let slot = established(&mut rig);
    let (mut image_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let first: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 32]).collect();
    assert_eq!(enc_deliver(&mut rig, &mut subscriber, &first), first);
    // Recording stops here: nothing is recorded during the run.
    let last = crate::wire_enc::take_seals()
        .into_iter()
        .filter(|record| record.context.domain == Domain::Sender)
        .max_by_key(|record| record.seq)
        .unwrap();
    let forged_keys = ChannelKeys::new(&[&crate::wire_keys::parse(
        "3-1.key",
        b"format=karyos-wire-key-v1\nkey_id=3\nfile_epoch=1\npurpose=channel\nprofile_id=16\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=9999999999999999999999999999999999999999999999999999999999999999\nchannel_id=7\nstream_id=6\n",
    )
    .unwrap()])
    .unwrap();
    let mut sealer = EncSealer::new(
        &forged_keys,
        None,
        last.context,
        crate::wire_enc::monotonic_ns,
    )
    .unwrap();
    // Sequences ahead of every genuine one of the run: each forged datagram
    // passes the replay precheck and is refused for its tag.
    sealer.key().set_next_seq(last.seq + 10 * rate * SECONDS);
    let pool: Arc<Vec<Vec<u8>>> = (0..POOL)
        .map(|_| {
            let mut bytes = vec![0_u8; MAX_SEALED];
            bytes[..last.frames.len()].copy_from_slice(&last.frames);
            let length = sealer
                .seal(&mut bytes, last.frames.len() + FORGED_PAD)
                .unwrap();
            bytes.truncate(length);
            bytes
        })
        .collect::<Vec<_>>()
        .into();
    let forged_length = pool[0].len();
    // The forger: a duplicate of the publisher's own socket, so its
    // datagrams name the bound publication's source, sending to the
    // receiver's bound endpoint.
    let receiver_address = rig.endpoints.local_address(b).unwrap();
    let refusals = |rig: &Rig| {
        rig.agents
            .receiver
            .role
            .enc_rejections(b, alias().stream_id)
            .unwrap()
    };
    let before = refusals(&rig);
    let epochs = rig.agents.receiver.role.enc_epochs(slot);
    let challenges = rig.agents.receiver.role.posted_challenges().len();
    let committed_before = rig.agents.receiver.counters().data_committed;

    let mut intakes: Vec<u64> = Vec::with_capacity(MAX_SAMPLES);
    let mut busy: Vec<u64> = Vec::with_capacity(MAX_SAMPLES);
    let mut out = vec![0_u8; 65_536];
    let mut allocating: Vec<(u64, u64, String)> = Vec::with_capacity(32);
    let mut message = [0_u8; 32];
    let (mut appended, mut back_pressured) = (0_u64, 0_u64);
    let (mut delivered, mut out_of_order, mut next_expected) = (0_u64, 0_u64, 0_u64);
    let (mut receiver_allocs, mut sender_allocs) = (0_u64, 0_u64);
    let (mut iterations, mut late_ns) = (0_u64, 0_u64);
    // The test-only logs reserved to their caps: what is counted is the
    // production path alone.
    rig.agents.receiver.role.reserve_test_logs();
    rig.agents.receiver.role.watch_length(forged_length);
    let base = rig.now;
    let total_ns = SECONDS * 1_000_000_000;
    let forged_rate = rate * invalid_percent / 100;
    let go = Arc::new(AtomicBool::new(false));
    // The flood, on its own thread, on its own schedule from the start
    // both loads share: forged sent, send calls refused, largest lag.
    let forgers = forged_rate.div_ceil(PER_FORGER).clamp(1, FORGERS);
    let floods: Vec<_> = (0..forgers)
        .map(|share| {
            let go = Arc::clone(&go);
            let pool = Arc::clone(&pool);
            let route = RouteAddr::new(receiver_address);
            let mut forger = rig.agents.sender.tx_socket(rig.publisher).unwrap();
            std::thread::spawn(move || {
                while !go.load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }
                let start = Instant::now();
                let (mut sent, mut refused, mut late_ns) = (0_u64, 0_u64, 0_u64);
                let mut batch: [&[u8]; SEND_BATCH] = [&[]; SEND_BATCH];
                loop {
                    let elapsed = u64::try_from(start.elapsed().as_nanos()).unwrap();
                    if elapsed >= total_ns {
                        break;
                    }
                    // This thread's share of the datagrams due by now.
                    let due =
                        (elapsed * forged_rate / 1_000_000_000 + forgers - 1 - share) / forgers;
                    let behind = due.saturating_sub(sent);
                    late_ns = late_ns.max(behind * forgers * 1_000_000_000 / forged_rate.max(1));
                    if behind == 0 {
                        // Nothing due: the core goes back to the agents.
                        std::thread::yield_now();
                        continue;
                    }
                    let count = usize::try_from(behind.min(SEND_BATCH as u64)).unwrap();
                    for (at, slot) in batch[..count].iter_mut().enumerate() {
                        #[allow(clippy::cast_possible_truncation, reason = "below POOL")]
                        let index = ((share + forgers * (sent + at as u64)) % POOL) as usize;
                        *slot = &pool[index];
                    }
                    match forger.send(&route, &batch[..count]) {
                        SendResult::Sent { sent: more, .. } if more > 0 => sent += more as u64,
                        _ => refused += 1,
                    }
                }
                (sent, refused, late_ns)
            })
        })
        .collect();
    go.store(true, Ordering::Release);
    let start = Instant::now();
    let done = AtomicBool::new(false);
    let mut phases = Phases::default();
    {
        // The receiver duty on its own thread, as `ThreadingMode::Dedicated`
        // runs it: nothing but its duty cycle, timed, on the shared clock.
        let receiver = &mut rig.agents.receiver;
        let (done, intakes, busy, allocating) = (&done, &mut intakes, &mut busy, &mut allocating);
        let (receiver_allocs, iterations) = (&mut receiver_allocs, &mut iterations);
        let receive = move || {
            while !done.load(Ordering::Acquire) {
                let elapsed = u64::try_from(start.elapsed().as_nanos()).unwrap();
                *iterations += 1;
                let now = base + elapsed;
                VIRTUAL_NOW.with(|cell| cell.set(now));
                // The receiver's complete intake: its duty cycle reads the
                // socket, where the flood and the valid load arrive,
                // verifies and refuses the forged datagrams and delivers
                // the valid ones.
                let timed = Instant::now();
                let (work, allocations) = count_allocations(|| receiver.do_work(now));
                let interval = u64::try_from(timed.elapsed().as_nanos()).unwrap();
                *receiver_allocs += allocations;
                if allocations > 0 && allocating.len() < allocating.capacity() {
                    allocating.push((elapsed, allocations, format!("{:?}", receiver.counters())));
                }
                if intakes.len() < MAX_SAMPLES {
                    intakes.push(interval);
                }
                if work.unwrap() > 0 && busy.len() < MAX_SAMPLES {
                    busy.push(interval);
                }
            }
        };
        // The valid side on this thread: appends, conductors, the sender
        // duty, the control plane and the subscriber. A panic here sets
        // `done` while unwinding, so the receiver stops and the scope's
        // join returns.
        with_receiver(done, receive, || {
            loop {
                let elapsed = u64::try_from(start.elapsed().as_nanos()).unwrap();
                if elapsed >= total_ns {
                    break;
                }
                rig.now = base + elapsed;
                let now = rig.now;
                VIRTUAL_NOW.with(|cell| cell.set(now));
                // Valid load on its schedule; a back-pressured append retries.
                let due = elapsed * rate / 1_000_000_000;
                let timed = Instant::now();
                while appended < due {
                    message[..8].copy_from_slice(&appended.to_le_bytes());
                    match rig.log.as_mut().unwrap().publications[0]
                        .append(&message, AppendOptions::default())
                        .unwrap()
                    {
                        AppendOutcome::Appended { .. } => appended += 1,
                        _ => {
                            back_pressured += 1;
                            break;
                        }
                    }
                }
                late_ns = late_ns.max((due - appended) * 1_000_000_000 / rate);
                let timed = phases.lap(0, timed);
                if let Some(log) = rig.log.as_mut() {
                    for conductor in &mut log.conductors {
                        let _ = conductor.duty_cycle().unwrap();
                    }
                }
                // The image's own conductor cleans and rotates its terms.
                let _ = image_conductor.duty_cycle().unwrap();
                let timed = phases.lap(1, timed);
                let sender = &mut rig.agents.sender;
                let (result, allocations) = count_allocations(|| sender.do_work(now));
                result.unwrap();
                sender_allocs += allocations;
                let timed = phases.lap(2, timed);
                rig.endpoints.poll(&rig.links, now, |_| {}, |_| {});
                rig.images
                    .poll(&rig.links.sessions, &mut LaneSource::heap(), |_| {});
                while let PollOutcome::Message { length, .. } = subscriber.poll(&mut out).unwrap() {
                    subscriber.acknowledge();
                    let index = u64::from_le_bytes(out[..8].try_into().unwrap());
                    if length != 32 || index != next_expected {
                        out_of_order += 1;
                    }
                    next_expected = index + 1;
                    delivered += 1;
                }
                let _ = phases.lap(3, timed);
            }
        });
    }
    let (mut forged_sent, mut send_refused, mut forged_late_ns) = (0_u64, 0_u64, 0_u64);
    for flood in floods {
        let (sent, refused, late) = flood.join().unwrap();
        forged_sent += sent;
        send_refused += refused;
        forged_late_ns = forged_late_ns.max(late);
    }
    let elapsed_s = start.elapsed().as_secs_f64();
    // Drain what is in flight, without load and without flood: the
    // forged datagrams still queued at the receiver's socket included.
    let (mut quiet, mut read) = (0_u32, rig.agents.receiver.role.watched_in());
    for _ in 0..2_000 {
        let now_read = rig.agents.receiver.role.watched_in();
        quiet = if now_read == read { quiet + 1 } else { 0 };
        read = now_read;
        if delivered == appended && quiet >= 10 {
            break;
        }
        rig.round(true);
        let _ = image_conductor.duty_cycle().unwrap();
        while let PollOutcome::Message { length, .. } = subscriber.poll(&mut out).unwrap() {
            subscriber.acknowledge();
            let index = u64::from_le_bytes(out[..8].try_into().unwrap());
            if length != 32 || index != next_expected {
                out_of_order += 1;
            }
            next_expected = index + 1;
            delivered += 1;
        }
    }
    let after = refusals(&rig);
    let forged = rig.agents.receiver.role.watched_in();
    let drops = forged_sent.saturating_sub(forged);
    let new_challenges = rig.agents.receiver.role.posted_challenges().len() - challenges;
    let counters = rig.agents.receiver.counters();
    let mut report = String::new();
    let _ = writeln!(
        report,
        "R4 encrypted (W1 L=32, F1 unicast, loopback): valid {rate}/s for {SECONDS} s, \
         invalid tags at {invalid_percent}% ({} /s)",
        rate * invalid_percent / 100
    );
    #[allow(clippy::cast_precision_loss, reason = "a reported rate")]
    let achieved = (
        appended as f64 / elapsed_s,
        forged_sent as f64 / elapsed_s,
        forged as f64 / elapsed_s,
    );
    let _ = writeln!(
        report,
        "achieved: valid {:.0}/s forged sent {:.0}/s received {:.0}/s over {elapsed_s:.3} s \
         (scheduled {rate}/s and {forged_rate}/s)",
        achieved.0, achieved.1, achieved.2,
    );
    let _ = writeln!(
        report,
        "valid appended={appended} back_pressured_appends={back_pressured} \
         max_schedule_lag={late_ns}ns delivered={delivered} out_of_order={out_of_order} \
         data_committed={}",
        counters.data_committed - committed_before
    );
    let _ = writeln!(
        report,
        "forged sent={forged_sent} received={forged} udp_drops={drops} \
         (refused send calls={send_refused} max_flood_lag={forged_late_ns}ns, length {forged_length}) \
         enc_tag={} enc_total={} (before: tag={} total={})",
        after.get(EncRejection::Tag) - before.get(EncRejection::Tag),
        after.total() - before.total(),
        before.get(EncRejection::Tag),
        before.total()
    );
    let _ = writeln!(report, "rejections after: {after:?}");
    let _ = writeln!(
        report,
        "verifier pool (ADR-0126): verifiers={} slots={} enc_verify_busy={} in_flight_after={}",
        verify.verifiers,
        verify.slots,
        after.get(EncRejection::VerifyBusy) - before.get(EncRejection::VerifyBusy),
        rig.agents.receiver.role.enc_in_flight()
    );
    let _ = writeln!(
        report,
        "allocations: receiver duties={receiver_allocs} sender duties={sender_allocs}"
    );
    let _ = writeln!(
        report,
        "state: new challenge entries={new_challenges} epochs before={epochs:?} after={:?}",
        rig.agents.receiver.role.enc_epochs(slot)
    );
    let _ = writeln!(
        report,
        "receiver duties (own thread): iterations={iterations} (refused below {} per second)",
        MIN_SAMPLES_PER_SECOND
    );
    let _ = writeln!(
        report,
        "valid side thread ms: append={} conductors={} sender={} control+subscriber={}",
        phases.0[0] / 1_000_000,
        phases.0[1] / 1_000_000,
        phases.0[2] / 1_000_000,
        phases.0[3] / 1_000_000,
    );
    for (at, allocations, counters) in &allocating {
        let _ = writeln!(
            report,
            "allocating duty at {at}ns: {allocations} ({counters})"
        );
    }
    let samples = intakes.len();
    percentiles(
        "receiver intake (socket read, forged verification, delivery), every poll",
        &mut intakes,
        &mut report,
    );
    percentiles(
        "receiver intake, polls that did work",
        &mut busy,
        &mut report,
    );
    // The report goes to stdout (run with --nocapture), and to a file in
    // the directory KARYOS_R4_OUT names, when set.
    let _ = std::io::Write::write_all(&mut std::io::stdout(), report.as_bytes());
    if let Some(dir) = std::env::var_os("KARYOS_R4_OUT") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(format!("r4-{rate}-{invalid_percent}.txt")),
            &report,
        )
        .unwrap();
    }

    // The load was sustained: an underloaded run measures nothing.
    let load = Load {
        appended,
        forged_sent,
        forged_received: forged,
        late_ns,
        samples,
    };
    if let Err(why) = sustained(rate, invalid_percent, load) {
        panic!(
            "{why}
{report}"
        );
    }
    assert_eq!(receiver_allocs, 0, "{report}");
    assert_eq!(sender_allocs, 0, "{report}");
    // Every forged datagram read is refused for its tag, or dropped before
    // its open when no verification slot was free (ADR-0126 decision 4,
    // which drops valid datagrams too: those are repaired).
    let tags = after.get(EncRejection::Tag) - before.get(EncRejection::Tag);
    let busy = after.get(EncRejection::VerifyBusy) - before.get(EncRejection::VerifyBusy);
    assert!(tags <= forged && tags + busy >= forged, "{report}");
    assert_eq!(after.total() - before.total(), tags + busy, "{report}");
    assert_eq!(delivered, appended, "{report}");
    assert_eq!(out_of_order, 0, "{report}");
    assert!(new_challenges <= 1, "{report}");
    assert_eq!(
        rig.agents.receiver.role.enc_epochs(slot),
        epochs,
        "{report}"
    );
    report
}

#[test]
#[ignore = "H10 R4 measurement: run explicitly in release"]
fn r4_encrypted_invalid_tags_at_10_percent() {
    let _ = r4(RATE_LOW, 10);
}

#[test]
#[ignore = "H10 R4 measurement: run explicitly in release"]
fn r4_encrypted_invalid_tags_at_100_percent() {
    let _ = r4(RATE_LOW, 100);
}

#[test]
#[ignore = "H10 R4 measurement: run explicitly in release"]
fn r4_encrypted_1m_invalid_tags_at_10_percent() {
    let _ = r4(RATE_HIGH, 10);
}

#[test]
#[ignore = "H10 R4 measurement: run explicitly in release"]
fn r4_encrypted_1m_invalid_tags_at_100_percent() {
    let _ = r4(RATE_HIGH, 100);
}

/// Sets the receiver's shutdown flag when dropped, also while the parent
/// side unwinds, so a scope joining a receiver that loops until the flag
/// is set cannot hang.
struct Shutdown<'a>(&'a AtomicBool);

impl Drop for Shutdown<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Runs `receive` on a scoped thread and `parent` on this one. `done` is
/// set when `parent` returns or panics, before the scope joins `receive`,
/// which must return once `done` is set; a panic of `parent` resumes after
/// the join.
fn with_receiver<R>(
    done: &AtomicBool,
    receive: impl FnOnce() + Send,
    parent: impl FnOnce() -> R,
) -> R {
    std::thread::scope(|scope| {
        let receiving = scope.spawn(receive);
        let shutdown = Shutdown(done);
        let result = parent();
        drop(shutdown);
        receiving.join().unwrap();
        result
    })
}

#[test]
fn a_parent_panic_stops_the_receiver_instead_of_hanging() {
    let (finished, outcome) = std::sync::mpsc::channel();
    // The run on its own thread: a hang fails the test after the timeout
    // instead of blocking it.
    std::thread::spawn(move || {
        let done = AtomicBool::new(false);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_receiver(
                &done,
                || {
                    while !done.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                },
                || -> u8 { panic!("injected parent panic") },
            )
        }));
        let _ = finished.send((unwound.is_err(), done.load(Ordering::Acquire)));
    });
    let (panicked, done) = outcome
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("the scope hung on the receiver after a parent panic");
    assert!(panicked, "the parent panic propagates after the join");
    assert!(done, "the shutdown flag was set while unwinding");
}

#[test]
fn an_underloaded_r4_run_is_refused() {
    let samples = usize::try_from(MIN_SAMPLES_PER_SECOND * SECONDS).unwrap();
    let load = |appended, forged_sent, forged_received, late_ns, samples| Load {
        appended,
        forged_sent,
        forged_received,
        late_ns,
        samples,
    };
    for rate in [RATE_LOW, RATE_HIGH] {
        let full = rate * SECONDS;
        let ok = |p, l| sustained(rate, p, l);
        assert_eq!(ok(10, load(full, full / 10, full / 10, 0, samples)), Ok(()));
        let least = full * 95 / 100;
        assert_eq!(
            ok(
                100,
                load(least, least, least * 95 / 100 + 1, MAX_LAG_NS, samples)
            ),
            Ok(())
        );
        // A stall before the first iteration: nothing sent at all.
        assert!(ok(10, load(0, 0, 0, 0, 0)).is_err());
        assert!(ok(100, load(full * 94 / 100, full, full, 0, samples)).is_err());
        assert!(
            ok(
                100,
                load(full, full * 94 / 100, full * 94 / 100, 0, samples)
            )
            .is_err()
        );
        assert!(
            ok(
                10,
                load(full, full / 10 * 94 / 100, full / 10 * 94 / 100, 0, samples)
            )
            .is_err()
        );
        // More than 5% of the forged datagrams sent lost by UDP.
        assert!(ok(100, load(full, full, full * 94 / 100, 0, samples)).is_err());
        assert!(ok(10, load(full, full / 10, full / 10 * 94 / 100, 0, samples)).is_err());
        // Received more than was sent: the count is not of the flood.
        assert!(ok(100, load(full, full, full + 1, 0, samples)).is_err());
        assert!(ok(100, load(full, full, full, MAX_LAG_NS + 1, samples)).is_err());
        assert!(ok(100, load(full, full, full, 0, samples - 1)).is_err());
    }
}
