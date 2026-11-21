// SPDX-License-Identifier: Apache-2.0

//! `karyos_publication_poll_outcomes` over an in-process guarded
//! publication (F7a-2): a guarded publication reaches the C ABI only
//! through a remote client, which never runs under Miri, so these tests
//! build one from the embedded driver's handle
//! (`Publication::from_handles`) and drive the driver on the test thread.

use karyos_client::{Client, Publication};
use karyos_driver::{EmbeddedDriver, GuardHandle};

use super::*;

/// A guarded publication's handles: the driver, its guard, the client
/// handle and the publication handle.
struct Guarded {
    driver: EmbeddedDriver,
    guard: GuardHandle,
    client: u64,
    publication: u64,
}

/// A driver with one guarded exclusive stream of `messages` reservations,
/// its guard reopened at epoch 2, and the stream's publication in the
/// publication table under an embedded client.
fn guarded(messages: u64) -> Guarded {
    let mut driver = EmbeddedDriver::new().unwrap();
    let mut config = stream_config(STREAM);
    // The guard's walker holds a spare-slot credit for the stream's life.
    config.buffer.spare_slots = 6;
    let stream = driver.add_stream(config).unwrap();
    let guard = driver.add_guard("orders").unwrap();
    driver.guard_stream(stream, guard, messages, None).unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    let handle = driver.publication(stream).unwrap();
    let publication = Publication::from_handles(vec![handle]).unwrap();
    let client = client::insert_embedded(Client::with_conductor(
        patient(driver.connect().unwrap()),
        test_context(),
    ))
    .unwrap();
    let publication = api::publication::insert_local(client, publication)
        .unwrap()
        .raw();
    Guarded {
        driver,
        guard,
        client: client.raw(),
        publication,
    }
}

/// Collects each record into the `Vec<Outcome>` at `context`.
unsafe extern "C" fn collect(context: *mut c_void, outcome: *const Outcome) {
    // SAFETY: the library hands a live `Outcome` for the call.
    let outcome = unsafe { *outcome };
    // SAFETY: the tests pass a live `Vec<Outcome>` as the context.
    unsafe { (*context.cast::<Vec<Outcome>>()).push(outcome) };
}

/// `karyos_publication_poll_outcomes` of `lane` into `records`: the status
/// and the count written.
fn poll(publication: u64, lane: u32, limit: u32, records: &mut Vec<Outcome>) -> (i32, u32) {
    let mut delivered = u32::MAX;
    // SAFETY: `collect` returns normally and `records` is a live
    // `Vec<Outcome>`; `delivered` is a live `u32`.
    let status = unsafe {
        karyos_publication_poll_outcomes(
            publication,
            lane,
            Some(collect),
            core::ptr::from_mut(records).cast(),
            limit,
            &mut delivered,
        )
    };
    (status, delivered)
}

/// What the handler's calls on its own publication answered.
#[derive(Default)]
struct Reentered {
    offer: i32,
    poll: i32,
    close: i32,
    client_close: i32,
    calls: u32,
}

/// Offers, polls and closes the publication and its client from inside
/// the handler.
unsafe extern "C" fn reenter(context: *mut c_void, _outcome: *const Outcome) {
    // SAFETY: the test passes a live `(u64, u64, Reentered)` as the
    // context: the publication, its client and the answers.
    let (publication, client, answers) = unsafe { &mut *context.cast::<(u64, u64, Reentered)>() };
    answers.offer = offer(*publication, b"x").0;
    answers.poll = poll(*publication, 0, 1, &mut Vec::new()).0;
    answers.close = karyos_publication_close(*publication);
    answers.client_close = karyos_client_close(*client);
    answers.calls += 1;
}

/// Each accepted message gets one `SUBMITTED` record once the driver's
/// walker has passed it, in sequence order, with the library's size, the
/// message's positions and the open epoch; a limit bounds a poll, a limit
/// of 0 consumes nothing, and a lane the stream does not configure is
/// refused. The handler runs while the publication is held: its calls on
/// that publication and its client are `KARYOS_E_REENTRANT`, and the poll
/// goes on. One driver for both, which Miri pays for once.
#[test]
fn records_reach_the_handler_which_cannot_reenter_its_publication() {
    let mut guarded = guarded(4);
    let mut positions = Vec::new();
    for payload in [b"a", b"b", b"c"] {
        let (status, done) = offer(guarded.publication, payload);
        assert_eq!(status, Status::Ok.code());
        positions.push(done.position);
    }
    let _ = guarded.driver.do_work().unwrap();
    let mut records = Vec::new();
    assert_eq!(poll(guarded.publication, 0, 0, &mut records), (0, 0));
    assert!(records.is_empty());
    assert_eq!(
        poll(guarded.publication, 1, 64, &mut records),
        (Status::InvalidLane.code(), 0)
    );
    // The bounded poll of ADR-0067: one record per call.
    assert_eq!(poll(guarded.publication, 0, 1, &mut records), (0, 1));
    // SAFETY: `collect` returns normally and `records` is a live
    // `Vec<Outcome>`; a null `delivered` is allowed.
    let status = unsafe {
        karyos_publication_poll_outcomes(
            guarded.publication,
            0,
            Some(collect),
            core::ptr::from_mut(&mut records).cast(),
            1,
            core::ptr::null_mut(),
        )
    };
    assert_eq!(status, Status::Ok.code());
    assert_eq!(poll(guarded.publication, 0, 64, &mut records), (0, 1));
    assert_eq!(poll(guarded.publication, 0, 64, &mut records), (0, 0));
    assert_eq!(records.len(), 3);
    for ((record, position), sequence) in records.iter().zip(&positions).zip(1..) {
        assert_eq!(record.size, 72);
        assert_eq!(record.size, size_of_u32::<Outcome>());
        assert_eq!(record.kind, OUTCOME_SUBMITTED);
        assert_eq!(record.sequence, sequence);
        assert_eq!((record.lane, record.receiver), (0, 0));
        assert_eq!(record.start, *position);
        assert!(record.end > record.start);
        assert_eq!(record.epoch, 2, "bound to the open epoch");
        assert_eq!(record.lost, 0);
    }

    assert_eq!(offer(guarded.publication, b"d").0, Status::Ok.code());
    assert_eq!(offer(guarded.publication, b"e").0, Status::Ok.code());
    let _ = guarded.driver.do_work().unwrap();
    let mut context = (guarded.publication, guarded.client, Reentered::default());
    let mut delivered = 0;
    // SAFETY: `reenter` returns normally and `context` is the live tuple it
    // reads; `delivered` is a live `u32`.
    let status = unsafe {
        karyos_publication_poll_outcomes(
            guarded.publication,
            0,
            Some(reenter),
            core::ptr::from_mut(&mut context).cast(),
            64,
            &mut delivered,
        )
    };
    assert_eq!((status, delivered), (Status::Ok.code(), 2));
    let reentrant = Status::Reentrant.code();
    let answers = &context.2;
    assert_eq!(answers.calls, 2);
    assert_eq!(
        (
            answers.offer,
            answers.poll,
            answers.close,
            answers.client_close
        ),
        (reentrant, reentrant, reentrant, reentrant)
    );
    assert_eq!(karyos_client_close(guarded.client), Status::Ok.code());
}

/// A guard close gates offers (`KARYOS_E_GATED`), and the walker ends the
/// incarnation's records with `ENDED`, after the accepted message's own.
/// It passed under Miri once on this batch (F7a-2, about 10 minutes); its
/// path adds no unsafe site to the test above.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_guard_close_gates_offers_and_ends_the_records() {
    let mut guarded = guarded(4);
    assert_eq!(offer(guarded.publication, b"a").0, Status::Ok.code());
    let closed = guarded.driver.close_guard(guarded.guard, 2);
    assert_eq!(closed, Ok(karyos_sys::guard::Closed::Now { epoch: 3 }));
    for _ in 0..3 {
        let _ = guarded.driver.do_work().unwrap();
    }
    assert_eq!(offer(guarded.publication, b"b").0, Status::Gated.code());
    for _ in 0..3 {
        let _ = guarded.driver.do_work().unwrap();
    }
    let mut records = Vec::new();
    assert_eq!(poll(guarded.publication, 0, 64, &mut records), (0, 2));
    let kinds: Vec<u32> = records.iter().map(|record| record.kind).collect();
    assert_eq!(kinds, [OUTCOME_SUBMITTED, OUTCOME_ENDED]);
    assert_eq!(records[1].reason, 1, "AbortReason::GUARD_CLOSED");
    assert_eq!(karyos_client_close(guarded.client), Status::Ok.code());
}

/// The arguments are checked before the handle, so no driver is needed: a
/// null handler and a misaligned count are refused with nothing written,
/// a lane no lane can be is refused before the handle is looked up, and a
/// stale handle writes 0 delivered, or nothing through a null count.
#[test]
fn the_arguments_are_checked_before_the_handle() {
    let stale = 0;
    let mut records = Vec::new();
    let mut delivered = 7;
    // SAFETY: a null handler is refused before any use.
    let null_handler = unsafe {
        karyos_publication_poll_outcomes(stale, 0, None, core::ptr::null_mut(), 64, &mut delivered)
    };
    assert_eq!(
        (null_handler, delivered),
        (Status::InvalidArgument.code(), 7)
    );
    let mut words = [7u32; 2];
    let misaligned = words
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(1)
        .cast::<u32>();
    // SAFETY: a misaligned `delivered` is refused before any use.
    let refused = unsafe {
        karyos_publication_poll_outcomes(
            stale,
            0,
            Some(collect),
            core::ptr::from_mut(&mut records).cast(),
            64,
            misaligned,
        )
    };
    assert_eq!(refused, Status::InvalidArgument.code());
    assert_eq!(words, [7, 7], "nothing written");
    assert_eq!(
        poll(stale, 9, 64, &mut records),
        (Status::InvalidLane.code(), 0)
    );
    assert_eq!(
        poll(stale, 0, 64, &mut records),
        (Status::InvalidHandle.code(), 0)
    );
    // SAFETY: `collect` returns normally and `records` is a live
    // `Vec<Outcome>`; a null `delivered` is allowed.
    let status = unsafe {
        karyos_publication_poll_outcomes(
            stale,
            0,
            Some(collect),
            core::ptr::from_mut(&mut records).cast(),
            64,
            core::ptr::null_mut(),
        )
    };
    assert_eq!(status, Status::InvalidHandle.code());
    assert!(records.is_empty());
}

/// An unguarded publication's lane has no records.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn an_unguarded_lane_has_no_records() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(stream_config(STREAM)).unwrap();
    let handle = driver.publication(stream).unwrap();
    let client = client::insert_embedded(Client::with_conductor(
        patient(driver.connect().unwrap()),
        test_context(),
    ))
    .unwrap();
    let publication =
        api::publication::insert_local(client, Publication::from_handles(vec![handle]).unwrap())
            .unwrap()
            .raw();
    assert_eq!(offer(publication, b"a").0, Status::Ok.code());
    let _ = driver.do_work().unwrap();
    let mut records = Vec::new();
    assert_eq!(poll(publication, 0, 64, &mut records), (0, 0));
    assert!(records.is_empty());
    assert_eq!(karyos_client_close(client.raw()), Status::Ok.code());
}

/// A publication built from the driver's own handle was never granted to
/// its client, so its close sends that client's driver no removal: the
/// handle is dropped, ending its lease.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn closing_a_local_publication_drops_its_handle() {
    let guarded = guarded(4);
    let client = Handle::from_raw(guarded.client);
    assert_eq!(client::publication_releases_failed(client), Ok(0));
    assert_eq!(
        karyos_publication_close(guarded.publication),
        Status::Ok.code()
    );
    // 1: the client's conductor refuses a handle it never granted
    // (`ForeignHandle`) before submitting anything, so the facade counts
    // the release as failed and drops the handle.
    assert_eq!(client::publication_releases_failed(client), Ok(1));
    assert_eq!(
        poll(guarded.publication, 0, 64, &mut Vec::new()),
        (Status::Closed.code(), 0)
    );
    assert_eq!(karyos_client_close(guarded.client), Status::Ok.code());
}

/// A concurrent handle is never guarded: lane 0 has no records, and every
/// other lane is invalid (GC-7).
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_concurrent_handle_has_no_records() {
    let (_driven, ours, _theirs) = super::driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let mut publication = 0;
    // SAFETY: a C string literal, a live `u64`, no detail.
    let status = unsafe {
        karyos_client_add_concurrent_publication(
            client,
            c"karyos:ipc".as_ptr(),
            STREAM_CONCURRENT,
            &mut publication,
            core::ptr::null_mut(),
        )
    };
    assert_eq!(status, Status::Ok.code());
    let mut records = Vec::new();
    assert_eq!(poll(publication, 0, 64, &mut records), (0, 0));
    assert_eq!(
        poll(publication, 1, 64, &mut records),
        (Status::InvalidLane.code(), 0)
    );
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// A client of the embedded driver's in-process command ring has no grant
/// to carry a guard binding, so the driver refuses it a guarded stream's
/// publication: `KARYOS_E_REFUSED` with the driver's code 6 (invalid
/// publication mode), as in Rust.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn an_embedded_client_is_refused_a_guarded_stream() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let mut config = stream_config(STREAM);
    config.buffer.spare_slots = 6;
    let stream = driver.add_stream(config).unwrap();
    let guard = driver.add_guard("orders").unwrap();
    driver.guard_stream(stream, guard, 4, None).unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    let conductor = patient(driver.connect().unwrap());
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = std::sync::Arc::clone(&stop);
    let _driven = super::Driven {
        stop,
        thread: Some(std::thread::spawn(move || {
            while !flag.load(std::sync::atomic::Ordering::Acquire) {
                let _ = driver.do_work().unwrap();
                std::thread::yield_now();
            }
        })),
    };
    let client = client::insert_embedded(Client::with_conductor(conductor, test_context()))
        .unwrap()
        .raw();
    let mut publication = 0;
    let mut detail = Detail {
        size: size_of_u32::<Detail>(),
        reserved: 0,
        code: 0,
        value: 0,
    };
    // SAFETY: a C string literal, a live `u64` and a live `karyos_detail`
    // with its size.
    let status = unsafe {
        karyos_client_add_publication(
            client,
            c"karyos:ipc".as_ptr(),
            STREAM,
            &mut publication,
            &mut detail,
        )
    };
    assert_eq!(status, Status::Refused.code());
    assert_eq!(detail.code, 6, "ErrorCode::InvalidPublicationMode");
    assert_eq!(publication, 0, "nothing opened");
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}
