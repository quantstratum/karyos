// SPDX-License-Identifier: Apache-2.0

//! The thread rules of the handles (`include/karyos.h`, "Threads") that a
//! run can check: no thread affinity, concurrent calls on one handle
//! refused with `BUSY`, and calls on different handles independent. The
//! compile-time half is `crate::threads`; reentry from a handler is
//! checked by `a_handler_that_reenters_its_subscription_is_refused` and
//! `outcomes::records_reach_the_handler_which_cannot_reenter_its_publication`,
//! a subscription held by its handler by
//! `a_subscription_held_by_another_thread_is_busy`, and the moves of a
//! conflated view and an Archive connection by
//! `conflated::a_view_moves_between_threads` and
//! `archive::a_connection_moves_between_threads`.

use std::sync::{Arc, Barrier};

use super::*;
use crate::handles::Handle;

/// Runs `f` on a thread of its own and returns its result.
fn on_a_thread<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
    std::thread::spawn(f).join().unwrap()
}

/// Holds `handle`'s slot of `table` on a thread of its own, as a call in
/// progress does, until the returned barrier is passed.
fn hold<T: Send + 'static>(
    table: &'static crate::handles::Table<T>,
    handle: u64,
) -> (Arc<Barrier>, std::thread::JoinHandle<()>) {
    let (entered, release) = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
    let thread = {
        let (entered, release) = (Arc::clone(&entered), Arc::clone(&release));
        std::thread::spawn(move || {
            table
                .with(Handle::from_raw(handle), |_| {
                    let _ = entered.wait();
                    let _ = release.wait();
                })
                .unwrap();
        })
    };
    let _ = entered.wait();
    (release, thread)
}

/// Every handle a client gives is used and closed on threads other than
/// the one that made it, and a claim is committed on a thread other than
/// the one that claimed it.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn handles_move_between_threads() {
    let (_driven, ours, _theirs) = driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let (publication, subscription) = on_a_thread(move || {
        let (status, publication) = add_publication(client);
        assert_eq!(status, Status::Ok.code());
        let (status, subscription) = add_subscription_of(client, STREAM);
        assert_eq!(status, Status::Ok.code());
        (publication, subscription)
    });
    on_a_thread(move || assert_eq!(offer(publication, b"moved").0, Status::Ok.code()));
    // The staged bytes' address crosses as a number: the claim's caller
    // owns them until the commit.
    let (claimed, staged) = on_a_thread(move || {
        let (status, claimed, staged) = claim(publication, 0, 6);
        assert_eq!(status, Status::Ok.code());
        (claimed, staged as usize)
    });
    on_a_thread(move || {
        // SAFETY: the claim's staged buffer of 6 bytes, live until the
        // commit below.
        unsafe { fill(staged as *mut u8, b"staged") };
        assert_eq!(commit(claimed).0, Status::Ok.code());
    });
    on_a_thread(move || {
        let mut seen = Seen::default();
        poll_until(subscription, client, &mut seen, 4, 2);
        assert_eq!(seen.messages, [b"moved".to_vec(), b"staged".to_vec()]);
        assert_eq!(karyos_subscription_close(subscription), Status::Ok.code());
        assert_eq!(karyos_publication_close(publication), Status::Ok.code());
    });
    on_a_thread(move || assert_eq!(karyos_client_close(client), Status::Ok.code()));
}

/// While a control call holds a client, its children's data-path calls
/// run, and the client's own calls, which hold it too, answer `BUSY` with
/// nothing done; they run once it returns. A child's close does not wait
/// for the client: it ends the child at once, and the client releases it
/// at its next call (`karyos.h`, Threads).
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_held_client_refuses_its_control_calls_not_its_childrens_data_path() {
    let (_driven, ours, _theirs) = driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let (_, publication) = add_publication(client);
    let (_, subscription) = add_subscription_of(client, STREAM);
    let (release, holder) = hold(client::clients(), client);
    // The children's data path holds only the child.
    assert_eq!(offer(publication, b"a").0, Status::Ok.code());
    let (status, claimed, staged) = claim(publication, 0, 1);
    assert_eq!(status, Status::Ok.code());
    // SAFETY: the claim's staged buffer of 1 byte.
    unsafe { fill(staged, b"b") };
    assert_eq!(commit(claimed).0, Status::Ok.code());
    let mut seen = Seen::default();
    assert_eq!(poll_into(subscription, &mut seen, 4).0, Status::Ok.code());
    // The client's own calls hold the client.
    assert_eq!(poll(client).0, Status::Busy.code());
    assert_eq!(add_publication(client).0, Status::Busy.code());
    assert_eq!(karyos_client_close(client), Status::Busy.code());
    // A child's close ends it now; its release waits for the client.
    assert_eq!(karyos_publication_close(publication), Status::Ok.code());
    assert_eq!(offer(publication, b"c").0, Status::Closed.code());
    let _ = release.wait();
    holder.join().unwrap();
    // The client's calls were refused with nothing done, and run now.
    poll_until(subscription, client, &mut seen, 4, 2);
    assert_eq!(seen.messages, [b"a".to_vec(), b"b".to_vec()]);
    assert_eq!(karyos_publication_close(publication), Status::Closed.code());
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// While another thread holds a publication, its offer, claim, commit,
/// outcome poll and close answer `BUSY` with nothing done; the staged
/// claim survives and commits once the publication is free.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_held_publication_is_busy_for_every_call() {
    let (_driven, ours, _theirs) = driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let (_, publication) = add_publication(client);
    let (_, subscription) = add_subscription_of(client, STREAM);
    let (status, claimed, staged) = claim(publication, 0, 1);
    assert_eq!(status, Status::Ok.code());
    // SAFETY: the claim's staged buffer of 1 byte.
    unsafe { fill(staged, b"x") };
    let (release, holder) = hold(api::publication::table(), publication);
    assert_eq!(offer(publication, b"a").0, Status::Busy.code());
    assert_eq!(claim(publication, 0, 1).0, Status::Busy.code());
    assert_eq!(commit(claimed).0, Status::Busy.code());
    unsafe extern "C" fn ignore(_context: *mut c_void, _outcome: *const Outcome) {}
    let mut delivered = u32::MAX;
    // SAFETY: a handler that reads nothing, no context, and a live
    // `uint32_t`.
    let polled = unsafe {
        karyos_publication_poll_outcomes(
            publication,
            0,
            Some(ignore),
            core::ptr::null_mut(),
            1,
            &mut delivered,
        )
    };
    assert_eq!(polled, Status::Busy.code());
    assert_eq!(karyos_publication_close(publication), Status::Busy.code());
    let _ = release.wait();
    holder.join().unwrap();
    assert_eq!(commit(claimed).0, Status::Ok.code());
    let mut seen = Seen::default();
    poll_until(subscription, client, &mut seen, 4, 1);
    assert_eq!(seen.messages, [b"x".to_vec()]);
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// A driver started on one thread is stopped on another and closed on a
/// third; while its thread runs, the caller's duty cycle answers `BUSY`.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_started_driver_is_stopped_and_closed_from_other_threads() {
    let mut options = core::mem::MaybeUninit::<DriverOptions>::zeroed();
    // SAFETY: a live, aligned, writable `DriverOptions`.
    let status = unsafe { karyos_driver_options_init(options.as_mut_ptr()) };
    assert_eq!(status, Status::Ok.code());
    // SAFETY: `karyos_driver_options_init` wrote every field.
    let options = unsafe { options.assume_init() };
    let mut driver = 0;
    // SAFETY: live, aligned pointers; no detail.
    let status = unsafe { karyos_driver_create(&options, &mut driver, core::ptr::null_mut()) };
    assert_eq!(status, Status::Ok.code());
    on_a_thread(move || {
        assert_eq!(
            karyos_driver_start(driver, api::client::IDLE_YIELD, 0),
            Status::Ok.code()
        );
    });
    let mut work = u32::MAX;
    // SAFETY: a live, aligned `uint32_t`.
    let status = unsafe { karyos_driver_do_work(driver, &mut work) };
    assert_eq!(status, Status::Busy.code());
    on_a_thread(move || assert_eq!(karyos_driver_stop(driver), Status::Ok.code()));
    on_a_thread(move || assert_eq!(karyos_driver_close(driver), Status::Ok.code()));
}
