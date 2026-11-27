// SPDX-License-Identifier: Apache-2.0

//! H10 R4 evidence for the `encrypted` class (wire-threat-model-manifest.md
//! sections 6.1 and 7; ADR-0114): the test-level equivalent of the R4
//! load, since the bench harness has no `encrypted` profile. A real
//! encrypted publication and subscription over loopback carry valid W1
//! traffic (`L` = 32, one message per append) at R2's two rates (100 000
//! and 1 000 000 messages/s) for a fixed time in wall-clock time, while datagrams forged under a wrong key (the
//! genuine context and frames, invalid tag) reach the receiver's real
//! intake at 10% or 100% of the valid rate. Each run states the
//! allocations of the forged intake and of each agent's duties, the
//! percentiles of the receiver's complete intake interval (the forged
//! datagrams of the iteration verified and refused, then the receiver's
//! duty cycle) and of its duty cycle alone, what was delivered and in
//! which order, the rejection counters and the state the flood left.
//! A run that does not sustain its load is refused: at least
//! [`MIN_LOAD_PERCENT`] of the scheduled valid and forged datagrams,
//! a schedule lag within [`MAX_LAG_NS`] and [`MIN_SAMPLES_PER_SECOND`]
//! intake samples per second. Ignored:
//! run explicitly in release (`cargo test --release -p karyos-driver
//! --lib r4_ -- --ignored --nocapture`); each run prints its report, and
//! writes it to `r4-<rate>-<p>.txt` in the directory `KARYOS_R4_OUT` names, when
//! set.

use std::fmt::Write as _;
use std::time::Instant;

use karyos_protocol::protection::aes_gcm_siv::{Domain, EncRejection};
use karyos_sys::alloc_count::count_allocations;
use karyos_sys::log_buffer::{AppendOptions, AppendOutcome, PollOutcome, Role};

use super::*;
use crate::wire_enc::{ChannelKeys, EncSealer, MAX_SEALED};

/// R2's lower valid rate (manifest 6.1), messages/s.
const RATE_LOW: u64 = 100_000;
/// R2's higher valid rate (manifest 6.1), messages/s.
const RATE_HIGH: u64 = 1_000_000;
/// Seconds each run lasts.
const SECONDS: u64 = 10;
/// Distinct forged datagrams, injected in a cycle.
const POOL: u64 = 4_096;
/// Receiver duties timed at most.
const MAX_SAMPLES: usize = 1 << 24;
/// The share of the scheduled valid and forged datagrams a run must
/// inject, or it is refused as underloaded.
const MIN_LOAD_PERCENT: u64 = 95;
/// The longest the valid load may fall behind its schedule: 10 ms, 1 000
/// messages at [`RATE_LOW`], 10 000 at [`RATE_HIGH`].
const MAX_LAG_NS: u64 = 10_000_000;
/// Intake intervals a run must time per second, at least (one per 1 ms on
/// average).
const MIN_SAMPLES_PER_SECOND: u64 = 1_000;

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

/// Whether a run at `rate` valid messages/s and `invalid_percent` sustained its load: at least
/// [`MIN_LOAD_PERCENT`] of the scheduled valid and forged datagrams, a
/// schedule lag within [`MAX_LAG_NS`] and enough intake samples.
fn sustained(
    rate: u64,
    appended: u64,
    forged: u64,
    invalid_percent: u64,
    late_ns: u64,
    samples: usize,
) -> Result<(), String> {
    let valid_target = rate * SECONDS;
    let forged_target = valid_target * invalid_percent / 100;
    if appended * 100 < valid_target * MIN_LOAD_PERCENT {
        return Err(format!("underloaded: {appended} valid of {valid_target}"));
    }
    if forged * 100 < forged_target * MIN_LOAD_PERCENT {
        return Err(format!("underloaded: {forged} forged of {forged_target}"));
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
    let (mut rig, b) = encrypted_rig();
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
    let pool: Vec<Vec<u8>> = (0..POOL)
        .map(|_| {
            let mut bytes = vec![0_u8; MAX_SEALED];
            bytes[..last.frames.len()].copy_from_slice(&last.frames);
            let length = sealer.seal(&mut bytes, last.frames.len()).unwrap();
            bytes.truncate(length);
            bytes
        })
        .collect();
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
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

    let mut duties: Vec<u64> = Vec::with_capacity(MAX_SAMPLES);
    let mut intakes: Vec<u64> = Vec::with_capacity(MAX_SAMPLES);
    let mut busy: Vec<u64> = Vec::with_capacity(MAX_SAMPLES);
    let mut out = vec![0_u8; 65_536];
    let mut allocating: Vec<(u64, u64, String)> = Vec::with_capacity(32);
    let counters_of = |rig: &Rig| format!("{:?}", rig.agents.receiver.counters());
    let mut message = [0_u8; 32];
    let (mut appended, mut back_pressured, mut forged) = (0_u64, 0_u64, 0_u64);
    let (mut delivered, mut out_of_order, mut next_expected) = (0_u64, 0_u64, 0_u64);
    let (mut forged_allocs, mut receiver_allocs, mut sender_allocs) = (0_u64, 0_u64, 0_u64);
    let (mut iterations, mut late_ns) = (0_u64, 0_u64);
    // The test-only logs reserved to their caps: what is counted is the
    // production path alone.
    rig.agents.receiver.role.reserve_test_logs();
    let base = rig.now;
    let start = Instant::now();
    let total_ns = SECONDS * 1_000_000_000;
    loop {
        let elapsed = u64::try_from(start.elapsed().as_nanos()).unwrap();
        if elapsed >= total_ns {
            break;
        }
        iterations += 1;
        rig.now = base + elapsed;
        let now = rig.now;
        VIRTUAL_NOW.with(|cell| cell.set(now));
        // Valid load on its schedule; a back-pressured append retries.
        let due = elapsed * rate / 1_000_000_000;
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
        if let Some(log) = rig.log.as_mut() {
            for conductor in &mut log.conductors {
                let _ = conductor.duty_cycle().unwrap();
            }
        }
        // The image's own conductor cleans and rotates its terms.
        let _ = image_conductor.duty_cycle().unwrap();
        let sender = &mut rig.agents.sender;
        let (result, allocations) = count_allocations(|| sender.do_work(now));
        result.unwrap();
        sender_allocs += allocations;
        // The receiver's intake: the flood at its share of the scheduled
        // valid rate, verified and refused, then the receiver's duty cycle.
        // The interval times both; the duty is also timed alone.
        let forged_due = due * invalid_percent / 100;
        let receiver = &mut rig.agents.receiver;
        let intake = Instant::now();
        let ((), allocations) = count_allocations(|| {
            while forged < forged_due {
                #[allow(clippy::cast_possible_truncation, reason = "below POOL")]
                let bytes = &pool[(forged % POOL) as usize];
                receiver
                    .role
                    .inject_datagram(&receiver.sessions, b, source, bytes, now);
                forged += 1;
            }
        });
        forged_allocs += allocations;
        let timed = Instant::now();
        let (work, allocations) = count_allocations(|| receiver.do_work(now));
        let duty = u64::try_from(timed.elapsed().as_nanos()).unwrap();
        let interval = u64::try_from(intake.elapsed().as_nanos()).unwrap();
        receiver_allocs += allocations;
        if allocations > 0 && allocating.len() < allocating.capacity() {
            allocating.push((elapsed, allocations, counters_of(&rig)));
        }
        if duties.len() < MAX_SAMPLES {
            duties.push(duty);
            intakes.push(interval);
        }
        if work.unwrap() > 0 && busy.len() < MAX_SAMPLES {
            busy.push(duty);
        }
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
    }
    // Drain what is in flight, without load and without flood.
    for _ in 0..2_000 {
        if delivered == appended {
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
    let new_challenges = rig.agents.receiver.role.posted_challenges().len() - challenges;
    let counters = rig.agents.receiver.counters();
    let mut report = String::new();
    let _ = writeln!(
        report,
        "R4 encrypted (W1 L=32, F1 unicast, loopback): valid {rate}/s for {SECONDS} s, \
         invalid tags at {invalid_percent}% ({} /s)",
        rate * invalid_percent / 100
    );
    let elapsed_s = start.elapsed().as_secs_f64();
    #[allow(clippy::cast_precision_loss, reason = "a reported rate")]
    let achieved = (appended as f64 / elapsed_s, forged as f64 / elapsed_s);
    let _ = writeln!(
        report,
        "achieved: valid {:.0}/s forged {:.0}/s over {elapsed_s:.3} s (scheduled {rate}/s and {}/s)",
        achieved.0,
        achieved.1,
        rate * invalid_percent / 100
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
        "forged injected={forged} enc_tag={} enc_total={} (before: tag={} total={})",
        after.get(EncRejection::Tag) - before.get(EncRejection::Tag),
        after.total() - before.total(),
        before.get(EncRejection::Tag),
        before.total()
    );
    let _ = writeln!(report, "rejections after: {after:?}");
    let _ = writeln!(
        report,
        "allocations: forged intake={forged_allocs} receiver duties={receiver_allocs} \
         sender duties={sender_allocs}"
    );
    let _ = writeln!(
        report,
        "state: new challenge entries={new_challenges} epochs before={epochs:?} after={:?}",
        rig.agents.receiver.role.enc_epochs(slot)
    );
    let _ = writeln!(
        report,
        "receiver duties: iterations={iterations} (refused below {} per second)",
        MIN_SAMPLES_PER_SECOND
    );
    for (at, allocations, counters) in &allocating {
        let _ = writeln!(
            report,
            "allocating duty at {at}ns: {allocations} ({counters})"
        );
    }
    let samples = intakes.len();
    percentiles(
        "receiver intake (forged verification + duty), every poll",
        &mut intakes,
        &mut report,
    );
    percentiles("receiver duty, every poll", &mut duties, &mut report);
    percentiles("receiver duty, polls that did work", &mut busy, &mut report);
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
    if let Err(why) = sustained(rate, appended, forged, invalid_percent, late_ns, samples) {
        panic!(
            "{why}
{report}"
        );
    }
    assert_eq!(forged_allocs, 0, "{report}");
    assert_eq!(receiver_allocs, 0, "{report}");
    assert_eq!(sender_allocs, 0, "{report}");
    assert_eq!(
        after.get(EncRejection::Tag) - before.get(EncRejection::Tag),
        forged,
        "{report}"
    );
    assert_eq!(after.total() - before.total(), forged, "{report}");
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

#[test]
fn an_underloaded_r4_run_is_refused() {
    for rate in [RATE_LOW, RATE_HIGH] {
        let full = rate * SECONDS;
        let samples = usize::try_from(MIN_SAMPLES_PER_SECOND * SECONDS).unwrap();
        assert_eq!(sustained(rate, full, full / 10, 10, 0, samples), Ok(()));
        assert_eq!(
            sustained(
                rate,
                full * 95 / 100,
                full * 95 / 100,
                100,
                MAX_LAG_NS,
                samples
            ),
            Ok(())
        );
        // A stall before the first iteration: nothing injected at all.
        assert!(sustained(rate, 0, 0, 10, 0, 0).is_err());
        assert!(sustained(rate, full * 94 / 100, full, 100, 0, samples).is_err());
        assert!(sustained(rate, full, full * 94 / 100, 100, 0, samples).is_err());
        assert!(sustained(rate, full, full / 10 * 94 / 100, 10, 0, samples).is_err());
        assert!(sustained(rate, full, full, 100, MAX_LAG_NS + 1, samples).is_err());
        assert!(sustained(rate, full, full, 100, 0, samples - 1).is_err());
    }
}
