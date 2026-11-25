// SPDX-License-Identifier: Apache-2.0

//! A remote client's guarded publication, end to end over the admission
//! socket (Linux; `quantstratum-docs: karyos/design/guards-and-abort.md`,
//! "The binding across processes", G-x3): the client takes the grant,
//! binds the outcome ring, the consumed cell and the guard words it was
//! granted, offers under the open guard and reads its `Submitted` records,
//! is gated once the guard closes and reads `Ended`, and detaches every
//! export on drop.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use karyos_client::ipc::{AttachError, RemoteClient, attach};
use karyos_client::{
    Client, ClientConcurrentPublication, ClientPublication, ConcurrentOfferOutcome, Context,
    OfferOutcome, Outcome,
};
use karyos_driver::{DriverConfig, EmbeddedDriver, IpcConfig, StreamConfig, SystemClock};
use karyos_protocol::cnc::{ErrorCode, StreamId, StreamKey};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode};
use karyos_sys::outcome_ring::{Kind, Record};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::SharedTerms;

type IpcDriver = EmbeddedDriver<SharedTerms>;

const KEY: StreamKey = StreamKey {
    stream_id: 2,
    session_id: 1,
};

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-grem-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn driver(dir: &Path) -> IpcDriver {
    let timeout = 5_000_000_000;
    EmbeddedDriver::with_ipc(
        DriverConfig::default(),
        IpcConfig {
            dir: dir.to_path_buf(),
            max_pending_hellos: 2,
            hello_timeout: timeout,
            max_outbound_per_client: 16,
            fetch_deadline: timeout,
            max_exports_per_client: 16,
            max_fetches_per_client: 4,
            max_regions_per_fetch: 4,
            max_fetch_bytes: 1 << 30,
            max_tools: karyos_driver::DEFAULT_MAX_TOOLS,
            client_send_buffer: None,
        },
        Box::new(SystemClock::new()),
    )
    .unwrap()
}

fn stream_config() -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 3,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 2,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

fn attach_serving(driver: &mut IpcDriver, dir: &Path) -> Result<RemoteClient, AttachError> {
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| attach(dir, Duration::from_secs(5), 16));
        while !handle.is_finished() {
            let _ = driver.do_work().unwrap();
            std::thread::yield_now();
        }
        handle.join().unwrap()
    })
}

/// Serves the driver while `client` runs on another thread.
fn serve_while<R: Send>(driver: &mut IpcDriver, client: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|scope| {
        let handle = scope.spawn(client);
        let start = Instant::now();
        while !handle.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(30), "client stuck");
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        handle.join().unwrap()
    })
}

fn serve_until(driver: &mut IpcDriver, mut done: impl FnMut(&IpcDriver) -> bool) {
    let start = Instant::now();
    while !done(driver) {
        assert!(start.elapsed() < Duration::from_secs(30), "timed out");
        let _ = driver.do_work().unwrap();
        std::thread::yield_now();
    }
}

fn counter(driver: &IpcDriver, label: &str) -> u64 {
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|index| match reader.read(index) {
            karyos_sys::counters::CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == label.as_bytes() => Some(value),
            _ => None,
        })
        .unwrap()
}

/// Outcome records until `done` holds of them, with the driver served on
/// the other thread.
fn outcomes_until(
    publication: &mut ClientPublication<SharedTerms>,
    mut done: impl FnMut(&[Record]) -> bool,
) -> Vec<Record> {
    let mut records = Vec::new();
    let start = Instant::now();
    while !done(&records) {
        assert!(start.elapsed() < Duration::from_secs(5), "saw {records:?}");
        let _ = publication
            .poll_outcomes(64, |_, record| records.push(record))
            .unwrap();
        std::thread::yield_now();
    }
    records
}

#[test]
fn a_remote_guarded_publication_reads_its_outcomes_and_detaches_on_drop() {
    let dir = dir("e2e");
    let mut driver = driver(&dir);
    let stream = driver.add_stream(stream_config()).unwrap();
    // A second guard first, so the stream's guard word is not word 0.
    let _ = driver.add_guard("other").unwrap();
    let guard = driver.add_guard("orders").unwrap();
    driver.guard_stream(stream, guard, 4, None).unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    let mut client = attach_serving(&mut driver, &dir).unwrap();

    // Under the open guard: three messages, three `Submitted` records at
    // their positions, bound to epoch 2.
    let (client, mut publication) = serve_while(&mut driver, move || {
        let _ = client.add_publication(KEY, true).unwrap();
        let mut fetchable = None;
        let start = Instant::now();
        while fetchable.is_none() {
            assert!(start.elapsed() < Duration::from_secs(5), "no completion");
            let _ = client.poll(usize::MAX, |completion| match completion.outcome {
                Outcome::Fetchable(grant) => fetchable = Some(grant),
                other => panic!("expected a fetchable grant, got {other:?}"),
            });
        }
        let mut publication = client.take_publication(&fetchable.unwrap()).unwrap();
        let binding = publication.guard().unwrap();
        assert_eq!(binding.epoch(), 2);
        let mut accepted = Vec::new();
        for value in [b"a", b"b", b"c"] {
            match publication.offer(value).unwrap() {
                OfferOutcome::Accepted { position, .. } => accepted.push(position),
                other => panic!("not accepted: {other:?}"),
            }
        }
        let records = outcomes_until(&mut publication, |records| records.len() >= 3);
        assert_eq!(records.len(), 3, "{records:?}");
        for (record, position) in records.iter().zip(&accepted) {
            assert_eq!(record.kind, Kind::Submitted);
            assert_eq!(record.start, *position);
            assert_eq!(record.epoch, 2);
        }
        assert_eq!(publication.guard().unwrap().outstanding(), 0);
        (client, publication)
    });

    // The guard closes: the handle reads it through the granted guard
    // words and is gated, and the walker ends the incarnation's records.
    let _ = driver.close_guard(guard, 2).unwrap();
    let (client, publication) = serve_while(&mut driver, move || {
        assert!(matches!(
            publication.offer(b"late").unwrap(),
            OfferOutcome::Gated
        ));
        let records = outcomes_until(&mut publication, |records| {
            records.iter().any(|record| record.kind == Kind::Ended)
        });
        assert!(records.iter().all(|record| record.kind != Kind::Submitted));
        (client, publication)
    });

    // Dropping the handle detaches all four exports: the log buffer, the
    // ring, the cell and the guard words.
    drop(publication);
    drop(client);
    serve_until(&mut driver, |driver| driver.clients() == 0);
    assert_eq!(counter(&driver, "grants exported"), 4);
    assert_eq!(counter(&driver, "grants detached"), 4);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The facade takes a guarded stream's publication from a remote driver
/// like any other, and reads its outcomes per lane with
/// `poll_outcomes_on`.
#[test]
fn the_facade_reads_a_remote_guarded_publications_outcomes() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let dir = dir("facade");
    let stop = Arc::new(AtomicBool::new(false));
    let (ready, started) = std::sync::mpsc::channel();
    let thread = {
        let (dir, stop) = (dir.clone(), Arc::clone(&stop));
        std::thread::spawn(move || {
            let mut driver = driver(&dir);
            let stream = driver.add_stream(stream_config()).unwrap();
            let guard = driver.add_guard("orders").unwrap();
            driver.guard_stream(stream, guard, 4, None).unwrap();
            assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
            ready.send(()).unwrap();
            while !stop.load(Ordering::Relaxed) {
                let _ = driver.do_work().unwrap();
                std::thread::sleep(Duration::from_micros(100));
            }
        })
    };
    started.recv().unwrap();
    let mut client = Client::connect(
        Context::builder()
            .dir(&dir)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap(),
    )
    .unwrap();
    // A subscriber connects the stream for the facade's offers.
    let _subscription = client
        .add_subscription("karyos:ipc", StreamId::new(2))
        .unwrap();
    let mut publication = client
        .add_exclusive_publication("karyos:ipc", StreamId::new(2))
        .unwrap();
    let start = Instant::now();
    let accepted = loop {
        assert!(start.elapsed() < Duration::from_secs(5), "never accepted");
        if let Ok(accepted) = publication.offer(b"guarded") {
            break accepted;
        }
        let _ = client.poll();
    };
    let mut records = Vec::new();
    let start = Instant::now();
    while records.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(5), "no outcome");
        let _ = publication
            .poll_outcomes_on(Lane::ZERO, 8, |_, record| records.push(record))
            .unwrap();
        std::thread::yield_now();
    }
    assert_eq!(records[0].kind, Kind::Submitted);
    assert_eq!(records[0].start, accepted.position());
    assert_eq!(records[0].epoch, 2);
    // A lane the stream does not configure is refused.
    assert!(
        publication
            .poll_outcomes_on(Lane::try_new(1).unwrap(), 8, |_, _| {})
            .is_err()
    );
    drop(publication);
    drop(client);
    stop.store(true, Ordering::Relaxed);
    thread.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// R-CORE-21 (karyos#740) across processes: a remote handle takes its rate
/// copy from the policy published in its outcome ring, and a change the
/// driver makes later reaches it on its slow path.
#[test]
fn a_remote_handle_follows_a_rate_policy_change() {
    use karyos_driver::{GuardRate, RateAuthority};
    use karyos_sys::rate_limit::{Rate, RatePolicy};

    let per_second = |per_second, burst| RatePolicy {
        messages: Rate { per_second, burst },
        bytes: None,
    };
    let dir = dir("rate");
    let mut driver = driver(&dir);
    let stream = driver.add_stream(stream_config()).unwrap();
    let guard = driver.add_guard("orders").unwrap();
    // One message a second, a burst of one: no refill between the offers.
    driver
        .guard_stream(
            stream,
            guard,
            4,
            Some(GuardRate::publication(per_second(1, 1))),
        )
        .unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    let mut client = attach_serving(&mut driver, &dir).unwrap();
    let (client, mut publication) = serve_while(&mut driver, move || {
        let _ = client.add_publication(KEY, true).unwrap();
        let mut fetchable = None;
        let start = Instant::now();
        while fetchable.is_none() {
            assert!(start.elapsed() < Duration::from_secs(5), "no completion");
            let _ = client.poll(usize::MAX, |completion| match completion.outcome {
                Outcome::Fetchable(grant) => fetchable = Some(grant),
                other => panic!("expected a fetchable grant, got {other:?}"),
            });
        }
        let mut publication = client.take_publication(&fetchable.unwrap()).unwrap();
        assert_eq!(publication.guard().unwrap().rate_tokens(), Some(1));
        assert!(matches!(
            publication.offer(b"a").unwrap(),
            OfferOutcome::Accepted { .. }
        ));
        assert_eq!(publication.offer(b"b").unwrap(), OfferOutcome::RateLimited);
        (client, publication)
    });
    // A million a second: the handle earns a token within microseconds.
    assert_eq!(
        driver.change_rate_policy(
            stream,
            1,
            per_second(1_000_000, 1),
            (RateAuthority::Administrator, 1)
        ),
        Ok(2)
    );
    let (client, publication) = serve_while(&mut driver, move || {
        let start = Instant::now();
        loop {
            match publication.offer(b"b").unwrap() {
                OfferOutcome::Accepted { .. } => break,
                OfferOutcome::RateLimited => {
                    assert!(
                        start.elapsed() < Duration::from_millis(500),
                        "never applied"
                    );
                }
                other => panic!("not accepted: {other:?}"),
            }
        }
        (client, publication)
    });
    drop(publication);
    drop(client);
    serve_until(&mut driver, |driver| driver.clients() == 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The #852 review (decided 2026-10-28 by QS-COORDINATOR) across
/// processes: a remote handle bound to a reincarnation reads when it began
/// from its ring (`outcome_ring::REINCARNATED_AT`) and starts its copy
/// empty then: bound at once, empty or nearly; bound 250 ms after, the
/// burst, as the reincarnation's gate.
#[test]
fn a_remote_handle_of_a_reincarnation_earns_since_it_began() {
    use karyos_driver::GuardRate;
    use karyos_sys::guard::Closed;
    use karyos_sys::rate_limit::{Rate, RatePolicy};

    let dir = dir("reincarnated");
    let mut driver = driver(&dir);
    let stream = driver.add_stream(stream_config()).unwrap();
    let guard = driver.add_guard("orders").unwrap();
    // Ten a second, a burst of two: 250 ms earns the burst, while a bind
    // delayed by up to 100 ms under load earns one token at most.
    driver
        .guard_stream(
            stream,
            guard,
            4,
            Some(GuardRate::publication(RatePolicy {
                messages: Rate {
                    per_second: 10,
                    burst: 2,
                },
                bytes: None,
            })),
        )
        .unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    let client = attach_serving(&mut driver, &dir).unwrap();
    // Takes a publication of the stream: its rate copy's tokens.
    let take = |client: RemoteClient| {
        let mut client = client;
        let _ = client.add_publication(KEY, true).unwrap();
        let mut fetchable = None;
        let start = Instant::now();
        while fetchable.is_none() {
            assert!(start.elapsed() < Duration::from_secs(5), "no completion");
            let _ = client.poll(usize::MAX, |completion| match completion.outcome {
                Outcome::Fetchable(grant) => fetchable = Some(grant),
                other => panic!("expected a fetchable grant, got {other:?}"),
            });
        }
        let publication = client.take_publication(&fetchable.unwrap()).unwrap();
        let tokens = publication.guard().unwrap().rate_tokens();
        (client, publication, tokens)
    };
    let (client, first, tokens) = serve_while(&mut driver, move || take(client));
    assert_eq!(tokens, Some(2), "the first incarnation starts full");
    // Reincarnated (close, drop, reopen); bound at once: empty, or one token
    // if the bind waited.
    assert_eq!(driver.close_guard(guard, 2), Ok(Closed::Now { epoch: 3 }));
    drop(first);
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.reopen_guard(guard, 3, 3), Ok(4));
    let (client, second, tokens) = serve_while(&mut driver, move || take(client));
    assert!(matches!(tokens, Some(0 | 1)), "{tokens:?}");
    // Reincarnated again, stamped 250 ms before it happens: the burst.
    assert_eq!(driver.close_guard(guard, 4), Ok(Closed::Now { epoch: 5 }));
    drop(second);
    let _ = driver.do_work().unwrap();
    driver
        .backdate_next_reincarnation(stream, 250_000_000)
        .unwrap();
    assert_eq!(driver.reopen_guard(guard, 5, 5), Ok(6));
    let (client, third, tokens) = serve_while(&mut driver, move || take(client));
    assert_eq!(tokens, Some(2));
    drop(third);
    drop(client);
    serve_until(&mut driver, |driver| driver.clients() == 0);
    let _ = std::fs::remove_dir_all(&dir);
}

fn concurrent_config(publishers: u8) -> StreamConfig {
    let mut config = stream_config();
    // A concurrent stream's reservation room and spares, as the driver's
    // own concurrent guarded tests use.
    config.buffer.spare_slots = 6;
    config.buffer.max_reserved = MIN_TERM_LENGTH / 16;
    config.buffer.publication = PublicationMode::Concurrent {
        publishers,
        allow_non_lse: true,
    };
    config
}

/// The completion of the client's last request: its grant, or its
/// refusal's code and detail.
fn completion(client: &mut RemoteClient) -> Outcome {
    let mut outcome = None;
    let start = Instant::now();
    while outcome.is_none() {
        assert!(start.elapsed() < Duration::from_secs(5), "no completion");
        let _ = client.poll(usize::MAX, |completion| outcome = Some(completion.outcome));
    }
    outcome.unwrap()
}

/// A concurrent handle's message records until `count` arrived, with the
/// driver served on the other thread.
fn concurrent_outcomes(
    publication: &mut ClientConcurrentPublication<SharedTerms>,
    count: usize,
) -> Vec<Record> {
    let mut records = Vec::new();
    let start = Instant::now();
    while records.len() < count {
        assert!(start.elapsed() < Duration::from_secs(5), "saw {records:?}");
        let _ = publication
            .poll_outcomes(64, |_, record| records.push(record))
            .unwrap();
        std::thread::yield_now();
    }
    records
}

/// karyos#1102 (d), ADR-0092 decisions 2, 3 and 6: two concurrent guarded
/// handles of one remote client, each granted its slot of the shared
/// outcome ring, read one record per message each and none of the
/// other's; a handle beyond `H` is refused naming `H`, and another
/// client's handle on the same incarnation with `GC-7-client`.
#[test]
fn remote_concurrent_guarded_handles_read_only_their_own_outcomes() {
    let dir = dir("shared");
    let mut driver = driver(&dir);
    let stream = driver.add_stream(concurrent_config(3)).unwrap();
    let guard = driver.add_guard("orders").unwrap();
    // `C_m = 2`: every handle's quota reserved at once fits half a term.
    driver.guard_stream(stream, guard, 2, None).unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    let mut client = attach_serving(&mut driver, &dir).unwrap();
    let mut other = attach_serving(&mut driver, &dir).unwrap();

    let (client, other, handles) = serve_while(&mut driver, move || {
        let mut handles = Vec::new();
        for _ in 0..2 {
            let _ = client.add_concurrent_publication(KEY, true).unwrap();
            let Outcome::Fetchable(grant) = completion(&mut client) else {
                panic!("expected a fetchable grant");
            };
            let publication = client.take_concurrent_publication(&grant).unwrap();
            assert_eq!(publication.guard().unwrap().epoch(), 2);
            handles.push(publication);
        }
        // Another client, with a publisher slot free on the same incarnation (GC-7-client).
        let _ = other.add_concurrent_publication(KEY, true).unwrap();
        let refused = completion(&mut other);
        assert!(
            matches!(
                refused,
                Outcome::Refused {
                    code: ErrorCode::InvalidPublicationMode,
                    ..
                }
            ),
            "{refused:?}"
        );
        // Interleaved offers: each handle reads exactly its own.
        let mut accepted = [Vec::new(), Vec::new()];
        for round in 0..2 {
            for (which, publication) in handles.iter_mut().enumerate() {
                let payload = [u8::try_from(which * 2 + round).unwrap()];
                match publication.offer(&payload).unwrap() {
                    ConcurrentOfferOutcome::Accepted { position, .. } => {
                        accepted[which].push(position);
                    }
                    other => panic!("not accepted: {other:?}"),
                }
            }
        }
        for (publication, positions) in handles.iter_mut().zip(&accepted) {
            let records = concurrent_outcomes(publication, 2);
            let starts: Vec<u64> = records.iter().map(|record| record.start).collect();
            assert_eq!(&starts, positions, "{records:?}");
            assert!(records.iter().all(|record| record.kind == Kind::Submitted));
            assert_eq!(publication.guard().unwrap().outstanding(), 0);
        }
        // A third handle takes the last slot. `H = 3` is the publisher slot
        // count, so a fourth comes only once one is dropped: its publisher
        // slot is free again once the driver read its detach, its ring slot
        // never within the incarnation, so it is refused with `H` as the
        // detail.
        let _ = client.add_concurrent_publication(KEY, true).unwrap();
        let Outcome::Fetchable(grant) = completion(&mut client) else {
            panic!("expected a third grant");
        };
        handles.push(client.take_concurrent_publication(&grant).unwrap());
        drop(handles.pop());
        let start = Instant::now();
        let refused = loop {
            assert!(start.elapsed() < Duration::from_secs(5), "slot never freed");
            let _ = client.add_concurrent_publication(KEY, true).unwrap();
            match completion(&mut client) {
                Outcome::Refused {
                    code: ErrorCode::PublicationTaken,
                    ..
                } => std::thread::yield_now(),
                other => break other,
            }
        };
        assert!(
            matches!(
                refused,
                Outcome::Refused {
                    code: ErrorCode::GuardHandlesExhausted,
                    detail: 3,
                }
            ),
            "{refused:?}"
        );
        (client, other, handles)
    });

    // Dropping the handles detaches every export: per handle (three) its
    // log buffer slot, the shared ring, its cell and the guard words.
    drop(handles);
    drop(client);
    drop(other);
    serve_until(&mut driver, |driver| driver.clients() == 0);
    assert_eq!(counter(&driver, "grants exported"), 12);
    assert_eq!(counter(&driver, "grants detached"), 12);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Review of #1157: after a guard close and reopen, a remote concurrent
/// handle registers on the fresh incarnation, bound to the new epoch,
/// rather than being refused on the sealed one.
#[test]
fn a_remote_concurrent_handle_after_a_reopen_binds_the_fresh_incarnation() {
    let dir = dir("reopen");
    let mut driver = driver(&dir);
    let stream = driver.add_stream(concurrent_config(2)).unwrap();
    let guard = driver.add_guard("orders").unwrap();
    driver.guard_stream(stream, guard, 2, None).unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    let _ = driver.close_guard(guard, 2).unwrap();
    assert_eq!(driver.reopen_guard(guard, 3, 3), Ok(4));
    let mut client = attach_serving(&mut driver, &dir).unwrap();
    let (client, publication) = serve_while(&mut driver, move || {
        let _ = client.add_concurrent_publication(KEY, true).unwrap();
        let granted = completion(&mut client);
        let Outcome::Fetchable(grant) = granted else {
            panic!("expected a fetchable grant, got {granted:?}");
        };
        let mut publication = client.take_concurrent_publication(&grant).unwrap();
        assert_eq!(publication.guard().unwrap().epoch(), 4);
        assert!(matches!(
            publication.offer(b"fresh").unwrap(),
            ConcurrentOfferOutcome::Accepted { .. }
        ));
        (client, publication)
    });
    drop(publication);
    drop(client);
    serve_until(&mut driver, |driver| driver.clients() == 0);
    let _ = std::fs::remove_dir_all(&dir);
}
