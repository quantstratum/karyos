// SPDX-License-Identifier: Apache-2.0

//! The Archive-backed rejoin over the C ABI (F9b; quantstratum-docs:
//! karyos/design/ffi-archive.md): `KARYOS_REJOIN_ARCHIVE` in the
//! subscription options, `karyos_subscription_rejoin_state`, and that a
//! rejoin's Archive streams leave nothing open on failure or at close.

use super::archive::{DATA, REQUESTS, RESPONSES, archive_options, served_archive_with};
use super::*;

/// An embedded client of `conductor`, and its Archive handle over the
/// fake Archive's control streams.
fn client_and_archive(conductor: karyos_client::ClientConductor) -> (u64, u64) {
    let client = client::insert_embedded(Client::with_conductor(conductor, test_context()))
        .unwrap()
        .raw();
    let options = ArchiveOptions {
        requests: REQUESTS,
        responses: RESPONSES,
        client_id: 7,
        ..archive_options()
    };
    let mut archive = 0;
    // SAFETY: live, aligned pointers of their stated sizes; no detail.
    let status =
        unsafe { karyos_archive_connect(client, &options, &mut archive, core::ptr::null_mut()) };
    assert_eq!(status, Status::Ok.code());
    (client, archive)
}

/// Options that rejoin from `archive`.
fn rejoining(archive: u64) -> SubscriptionOptions {
    SubscriptionOptions {
        role: ROLE_OPTIONAL,
        rejoin: REJOIN_ARCHIVE,
        archive,
        replay_stream_id: 1040,
        secondary: REJOIN_AT_HEAD,
        ..subscription_defaults()
    }
}

/// `karyos_client_add_subscription_with` of [`DATA`] with `options`.
fn add(client: u64, options: &SubscriptionOptions) -> (i32, u64) {
    // SAFETY: `options` is live and its stated size.
    unsafe { add_subscription_with(client, DATA, options) }
}

/// `karyos_subscription_rejoin_state`: the status and what it wrote.
fn state(subscription: u64) -> (i32, SubscriptionRejoin) {
    let mut state = SubscriptionRejoin {
        size: size_of_u32::<SubscriptionRejoin>(),
        recovering: 7,
        merge_failure: 7,
        reserved: 7,
    };
    // SAFETY: a live, aligned struct of its stated size.
    let status = unsafe { karyos_subscription_rejoin_state(subscription, &mut state) };
    (status, state)
}

/// A subscription added with `KARYOS_REJOIN_ARCHIVE` delivers the live
/// stream as any other, and reads not recovering with no failure; a
/// subscription that does not rejoin reads the same.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_rejoining_subscription_reads_live_and_reports_its_state() {
    let (_driven, _archive, conductor) = served_archive_with(2);
    let (client, archive) = client_and_archive(conductor);
    let (status, subscription) = add(client, &rejoining(archive));
    assert_eq!(status, Status::Ok.code());
    let (status, plain) = add(client, &subscription_defaults());
    assert_eq!(status, Status::Ok.code());
    for handle in [subscription, plain] {
        let (status, read) = state(handle);
        assert_eq!(status, Status::Ok.code());
        assert_eq!(
            (
                read.size,
                read.recovering,
                read.merge_failure,
                read.reserved
            ),
            (16, 0, MERGE_NONE, 0)
        );
    }
    let (_, publication) = add_publication_of(client, DATA);
    assert_eq!(offer(publication, b"live").0, Status::Ok.code());
    let mut seen = Seen::default();
    poll_until(subscription, client, &mut seen, 4, 1);
    assert_eq!(seen.messages, [b"live".to_vec()]);
    // The Archive handle is only a factory: closing it leaves the rejoin.
    assert_eq!(karyos_archive_close(archive), Status::Ok.code());
    assert_eq!(offer(publication, b"after").0, Status::Ok.code());
    let mut after = Seen::default();
    poll_until(subscription, client, &mut after, 4, 1);
    assert_eq!(after.messages, [b"after".to_vec()]);
    assert_eq!(karyos_client_close(client), Status::Ok.code());
    assert_eq!(state(subscription).0, Status::Closed.code());
}

/// A rejoin takes one request publisher of its own and releases it at its
/// subscription's close: with two publishers, the Archive handle's and
/// one, a second rejoin is refused until the first closes, then takes its
/// slot. A refused rejoin leaves its subscription removed: repeated
/// refusals never use up the stream's subscriber slots.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_rejoin_holds_one_publisher_slot_and_releases_it_at_close() {
    let (_driven, _archive, conductor) = served_archive_with(2);
    let (client, archive) = client_and_archive(conductor);
    let (status, first) = add(client, &rejoining(archive));
    assert_eq!(status, Status::Ok.code());
    // More refusals than the stream has subscriber slots (4).
    for _ in 0..6 {
        let (status, refused) = add(client, &rejoining(archive));
        assert_eq!(status, Status::Refused.code());
        assert_eq!(refused, u64::MAX, "nothing written");
    }
    assert_eq!(karyos_subscription_close(first), Status::Ok.code());
    let (status, second) = add(client, &rejoining(archive));
    assert_eq!(status, Status::Ok.code());
    let (status, plain) = add(client, &subscription_defaults());
    assert_eq!(status, Status::Ok.code(), "a subscriber slot is still free");
    assert_ne!(second, plain);
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// The Archive must be the client's own, a chosen id must fit 32 bits,
/// and the handle must be an Archive's; nothing is opened otherwise.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_rejoin_checks_its_archive_and_its_id() {
    let (_driven, _archive, conductor) = served_archive_with(4);
    let (client, archive) = client_and_archive(conductor);
    // A client of another driver: its Archive is not ours.
    let (_other_driven, _other_archive, other_conductor) = served_archive_with(2);
    let (other_client, other_archive) = client_and_archive(other_conductor);
    for (options, expected) in [
        (rejoining(other_archive), Status::InvalidArgument),
        (
            SubscriptionOptions {
                archive_client_id: u64::from(u32::MAX) + 1,
                ..rejoining(archive)
            },
            Status::InvalidArgument,
        ),
        (rejoining(0), Status::InvalidHandle),
        (rejoining(client), Status::InvalidHandle),
    ] {
        let (status, subscription) = add(client, &options);
        assert_eq!(status, expected.code());
        assert_eq!(subscription, u64::MAX, "nothing written");
    }
    // A chosen id is the caller's; 0 takes one of the library's.
    for client_id in [9, 0] {
        let (status, _) = add(
            client,
            &SubscriptionOptions {
                archive_client_id: client_id,
                ..rejoining(archive)
            },
        );
        assert_eq!(status, Status::Ok.code(), "id {client_id}");
    }
    assert_eq!(karyos_client_close(client), Status::Ok.code());
    assert_eq!(karyos_client_close(other_client), Status::Ok.code());
}

/// The state's sized write, with no driver (the MIRI row): a struct of a
/// newer header keeps its tail, and a failure is written as its code.
#[test]
fn the_rejoin_state_is_written_by_the_callers_size() {
    /// A struct of a newer header: one more field, which stays untouched.
    #[repr(C)]
    struct Newer {
        state: SubscriptionRejoin,
        later: u64,
    }
    let mut newer = Newer {
        state: SubscriptionRejoin {
            size: size_of_u32::<Newer>(),
            recovering: 7,
            merge_failure: 7,
            reserved: 7,
        },
        later: u64::MAX,
    };
    let failure = karyos_client::MergeError::Live(karyos_client::ClientError::Timeout);
    // SAFETY: `newer` is live, aligned and its stated size.
    unsafe { write_rejoin_state((&raw mut newer).cast(), true, Some(&failure)) };
    assert_eq!(
        (
            newer.state.size,
            newer.state.recovering,
            newer.state.merge_failure,
            newer.state.reserved
        ),
        (16, 1, 9, 0)
    );
    assert_eq!(newer.later, u64::MAX);
    let mut exact = SubscriptionRejoin {
        size: 16,
        recovering: 7,
        merge_failure: 7,
        reserved: 7,
    };
    // SAFETY: `exact` is live, aligned and its stated size.
    unsafe { write_rejoin_state(&mut exact, false, None) };
    assert_eq!((exact.recovering, exact.merge_failure), (0, MERGE_NONE));
    // The arguments are checked before the handle: a null or short struct
    // is refused with nothing written, whatever the handle.
    // SAFETY: a null pointer, refused before any use.
    let status = unsafe { karyos_subscription_rejoin_state(0, core::ptr::null_mut()) };
    assert_eq!(status, Status::InvalidArgument.code());
    let mut short = SubscriptionRejoin {
        size: 12,
        recovering: 7,
        merge_failure: 7,
        reserved: 7,
    };
    // SAFETY: a live struct; its size is below the first version's.
    let status = unsafe { karyos_subscription_rejoin_state(0, &mut short) };
    assert_eq!(status, Status::InvalidArgument.code());
    assert_eq!((short.recovering, short.merge_failure), (7, 7));
    assert_eq!(state(0).0, Status::InvalidHandle.code());
}

/// The state's arguments are checked first, and its struct is written by
/// the caller's size, for a subscription that does not rejoin.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn the_rejoin_state_checks_its_arguments_and_writes_by_size() {
    let (_driven, ours, _theirs) = driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let (status, subscription) = add_subscription_of(client, STREAM);
    assert_eq!(status, Status::Ok.code());
    // SAFETY: a null pointer, refused before any use.
    let status = unsafe { karyos_subscription_rejoin_state(subscription, core::ptr::null_mut()) };
    assert_eq!(status, Status::InvalidArgument.code());
    let mut short = SubscriptionRejoin {
        size: 12,
        recovering: 7,
        merge_failure: 7,
        reserved: 7,
    };
    // SAFETY: a live struct; its size is below the first version's.
    let status = unsafe { karyos_subscription_rejoin_state(subscription, &mut short) };
    assert_eq!(status, Status::InvalidArgument.code());
    assert_eq!((short.recovering, short.merge_failure), (7, 7));
    /// A struct of a newer header: one more field, which stays untouched.
    #[repr(C)]
    struct Newer {
        state: SubscriptionRejoin,
        later: u64,
    }
    let mut newer = Newer {
        state: SubscriptionRejoin {
            size: size_of_u32::<Newer>(),
            recovering: 7,
            merge_failure: 7,
            reserved: 7,
        },
        later: u64::MAX,
    };
    // SAFETY: `newer` is live and its stated size.
    let status = unsafe { karyos_subscription_rejoin_state(subscription, (&raw mut newer).cast()) };
    assert_eq!(status, Status::Ok.code());
    assert_eq!(
        (
            newer.state.size,
            newer.state.recovering,
            newer.state.merge_failure
        ),
        (16, 0, MERGE_NONE)
    );
    assert_eq!(newer.later, u64::MAX);
    assert_eq!(state(0).0, Status::InvalidHandle.code());
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// Each merge failure has its code, and one this ABI version does not
/// name is `KARYOS_MERGE_OTHER`'s through the match's wildcard.
#[test]
fn each_merge_failure_has_its_code() {
    use karyos_client::{ClientError, MergeError, Overrun};
    assert_eq!(
        merge_code(&MergeError::ReplayOverrun(Overrun::new(0, 1, 1))),
        5
    );
    assert_eq!(merge_code(&MergeError::Replay(ClientError::Timeout)), 7);
    assert_eq!(
        merge_code(&MergeError::LiveOverrun(Overrun::new(0, 1, 1))),
        8
    );
    assert_eq!(merge_code(&MergeError::Live(ClientError::Timeout)), 9);
}
