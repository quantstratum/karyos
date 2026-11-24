// SPDX-License-Identifier: Apache-2.0

//! A recording's reader over a driver stream: the roles it admits, the
//! publisher a required one bounds, the lap an optional one rejoins
//! from, and the cell a dropped one frees.

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use karyos_client::{ClientPublication, OfferOutcome};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    LogBufferConfig, LossPolicy, PublicationMode, ReadError, ReadOrigin, ReadOutcome, Role,
};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use super::*;
use crate::embedded::StreamConfig;

const MESSAGE: usize = 1000;

fn stream() -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 4,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 42,
            claim_deadline: 100,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

/// Offers until the publication stops accepting, running the driver
/// between offers; returns how many it accepted.
fn offer_until_refused<T: StreamTerms>(
    driver: &mut EmbeddedDriver<T>,
    publication: &mut ClientPublication<T>,
    most: usize,
) -> usize {
    let mut accepted = 0;
    let mut refused = 0;
    while accepted < most && refused < 16 {
        match publication.offer(&[7; MESSAGE]).unwrap() {
            OfferOutcome::Accepted { .. } => {
                accepted += 1;
                refused = 0;
            }
            _ => refused += 1,
        }
        driver.do_work().unwrap();
    }
    accepted
}

/// Reads and acknowledges everything committed.
fn drain<T: StreamTerms>(reader: &mut LaneReader<T>) -> u64 {
    let mut out = vec![0u8; usize::try_from(MIN_TERM_LENGTH).unwrap()];
    loop {
        let from = reader.position();
        match reader.read_committed(from, ReadOrigin::Cursor, &mut out) {
            Ok(ReadOutcome::Copied { next, .. } | ReadOutcome::Canonical { next, .. }) => {
                reader.sent(next).unwrap();
            }
            Ok(ReadOutcome::Pending) | Err(ReadError::Retry) => return reader.position(),
            Err(error) => panic!("{error:?}"),
        }
    }
}

/// An observer, a walker or a conductor cell is not a recording: refused
/// before anything is admitted, and no occupant id is spent.
#[test]
fn a_recording_reader_admits_only_required_and_optional() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = driver.add_stream(stream()).unwrap();
    let before = driver.next_export;
    for role in [Role::Observer, Role::Walker] {
        assert!(
            matches!(
                driver.recording_reader(handle, role),
                Err(DriverError::Sys(SysError::InvalidPublicationMode { .. }))
            ),
            "{role:?}"
        );
    }
    assert_eq!(driver.next_export, before);
    // With every cell taken, the role is still refused as a role: the
    // check comes before the admission, which would refuse for room.
    let mut held = Vec::new();
    while let Ok(subscription) = driver.subscribe(handle, Role::Observer) {
        held.push(subscription);
    }
    assert!(!held.is_empty());
    assert!(matches!(
        driver.recording_reader(handle, Role::Observer),
        Err(DriverError::Sys(SysError::InvalidPublicationMode { .. }))
    ));
    drop(held);
    let required = driver.recording_reader(handle, Role::Required).unwrap();
    let optional = driver.recording_reader(handle, Role::Optional).unwrap();
    assert_eq!(driver.next_export, before + 2);
    drop((required, optional));
}

/// A required recording bounds the publisher until it reads and
/// acknowledges; dropping it frees the publisher.
#[test]
fn a_required_recording_bounds_the_publisher() {
    required_bounds_the_publisher(&mut EmbeddedDriver::new().unwrap());
}

fn required_bounds_the_publisher<T: StreamTerms>(driver: &mut EmbeddedDriver<T>) {
    let handle = driver.add_stream(stream()).unwrap();
    let (mut reader, lease) = driver
        .recording_reader(handle, Role::Required)
        .unwrap()
        .into_parts();
    let mut publication = driver.publication(handle).unwrap();
    let most = 4 * usize::try_from(MIN_TERM_LENGTH).unwrap() / MESSAGE;
    let first = offer_until_refused(driver, &mut publication, most);
    assert!(first > 0 && first < most, "bounded: {first} of {most}");
    // Reading and acknowledging opens the window again.
    assert!(drain(&mut reader) > 0);
    driver.do_work().unwrap();
    assert!(offer_until_refused(driver, &mut publication, most) > 0);
    // Dropped, it no longer bounds anything.
    drop((reader, lease));
    driver.do_work().unwrap();
    assert_eq!(offer_until_refused(driver, &mut publication, most), most);
}

/// The stream's publication limit and head, as its conductor published
/// and observed them.
fn limit_and_head<T: StreamTerms>(
    driver: &mut EmbeddedDriver<T>,
    handle: StreamHandle,
) -> (u64, u64) {
    let stream = driver.stream(handle).unwrap();
    (stream.conductor.limit(), stream.conductor.head().unwrap())
}

/// Runs a duty cycle and returns the limit it published, asserting that
/// it is not below `last` (SPEC §4: limits never decrease).
fn cycle<T: StreamTerms>(
    driver: &mut EmbeddedDriver<T>,
    handle: StreamHandle,
    last: &mut u64,
) -> u64 {
    driver.do_work().unwrap();
    let (limit, _) = limit_and_head(driver, handle);
    assert!(limit >= *last, "the limit decreased: {limit} below {last}");
    *last = limit;
    limit
}

/// Reads and acknowledges one chunk of at most `bytes`; returns the
/// reader's position.
fn read_some<T: StreamTerms>(reader: &mut LaneReader<T>, bytes: usize) -> u64 {
    let mut out = vec![0u8; bytes];
    let from = reader.position();
    match reader.read_committed(from, ReadOrigin::Cursor, &mut out) {
        Ok(ReadOutcome::Copied { next, .. } | ReadOutcome::Canonical { next, .. }) => {
            reader.sent(next).unwrap();
        }
        other => panic!("{other:?}"),
    }
    reader.position()
}

/// Required set transitions with a required Archive only (SPEC §4 and
/// §13, contract-traceability plan item 6): a stream without
/// `allow_unconnected` whose only participant is a required recording is
/// connected and bounded by the recording's position plus the window;
/// once the recording leaves, the limit follows the head plus the window
/// and stays finite, and a required recording joining later bounds the
/// publisher again. The limit never decreases across any transition.
#[test]
fn test_recording_required_alone_connects_and_bounds_until_it_leaves() {
    required_recording_alone(&mut EmbeddedDriver::new().unwrap());
}

fn required_recording_alone<T: StreamTerms>(driver: &mut EmbeddedDriver<T>) {
    let window = u64::from(MIN_TERM_LENGTH / 2);
    let most = 4 * usize::try_from(MIN_TERM_LENGTH).unwrap() / MESSAGE;
    let handle = driver
        .add_stream(StreamConfig {
            allow_unconnected: false,
            ..stream()
        })
        .unwrap();
    let mut publication = driver.publication(handle).unwrap();
    // Control: without any participant the strict stream is not connected.
    assert_eq!(
        publication.offer(&[7; MESSAGE]).unwrap(),
        OfferOutcome::NotConnected
    );
    let (mut reader, lease) = driver
        .recording_reader(handle, Role::Required)
        .unwrap()
        .into_parts();
    let mut last = cycle(driver, handle, &mut 0);

    // 1. The recording alone connects the stream.
    assert_eq!(
        publication.offer(&[7; MESSAGE]).unwrap(),
        OfferOutcome::Accepted {
            lane: Lane::ZERO,
            position: 0
        }
    );

    // 2. While it lags, the publisher is bounded by its position plus the
    // window; reading moves the limit up with it, never down.
    let accepted = offer_until_refused(driver, &mut publication, most);
    assert!(
        accepted > 0 && accepted + 1 < most,
        "bounded: {accepted} of {most}"
    );
    let limit = cycle(driver, handle, &mut last);
    let (_, head) = limit_and_head(driver, handle);
    assert_eq!(limit, reader.position() + window);
    let framed = 2 * u64::try_from(MESSAGE).unwrap();
    assert!(
        head <= limit && limit - head < framed,
        "refused at the limit"
    );
    for _ in 0..3 {
        let position = read_some(&mut reader, 4 * MESSAGE);
        let limit = cycle(driver, handle, &mut last);
        assert_eq!(limit, position + window, "follows the recording");
        let _ = offer_until_refused(driver, &mut publication, most);
        let (limit, head) = limit_and_head(driver, handle);
        assert!(head <= limit, "head {head} above limit {limit}");
        assert_eq!(cycle(driver, handle, &mut last), position + window);
    }

    // 3. The recording leaves: no required participant remains. The limit
    // moves to the head snapshot plus the window, and with no participant
    // at all the strict stream is not connected and appends nothing.
    let lagged = reader.position();
    let (_, head) = limit_and_head(driver, handle);
    assert!(head > lagged, "the recording lagged the head");
    drop((reader, lease));
    let limit = cycle(driver, handle, &mut last);
    assert_eq!(limit, head + window, "head snapshot plus the window");
    assert_eq!(
        publication.offer(&[7; MESSAGE]).unwrap(),
        OfferOutcome::NotConnected
    );
    assert_eq!(limit_and_head(driver, handle).1, head, "appended nothing");
    // An optional reader connects it again without bounding it: the
    // limit follows the head across terms and stays finite.
    let optional = driver.subscribe(handle, Role::Optional).unwrap();
    for _ in 0..8 {
        let accepted = offer_until_refused(driver, &mut publication, most / 8);
        assert_eq!(accepted, most / 8, "unbounded by the optional reader");
        let (_, head) = limit_and_head(driver, handle);
        let limit = cycle(driver, handle, &mut last);
        assert_eq!(limit, head + window, "follows the head");
    }
    drop(optional);
    let _ = cycle(driver, handle, &mut last);

    // 4. A required recording joining later bounds the publisher again, at
    // its join position (the head) plus the window: not below the limit
    // already published.
    let (_, join) = limit_and_head(driver, handle);
    let (reader, lease) = driver
        .recording_reader(handle, Role::Required)
        .unwrap()
        .into_parts();
    assert_eq!(reader.position(), join, "joins at the head");
    let accepted = offer_until_refused(driver, &mut publication, most);
    assert!(
        accepted > 0 && accepted + 1 < most,
        "bounded again: {accepted} of {most}"
    );
    let limit = cycle(driver, handle, &mut last);
    assert_eq!(limit, join + window);
    let (_, head) = limit_and_head(driver, handle);
    assert!(head <= limit);
    let _ = offer_until_refused(driver, &mut publication, most);
    assert_eq!(limit_and_head(driver, handle).1, head, "still bounded");
    drop((reader, lease));
}

/// An optional recording never bounds the publisher: lapped, its read is
/// `Unavailable`, and it rejoins at the head and reads what follows.
#[test]
fn an_optional_recording_is_lapped_and_rejoins_at_the_head() {
    optional_is_lapped_and_rejoins(&mut EmbeddedDriver::new().unwrap());
}

fn optional_is_lapped_and_rejoins<T: StreamTerms>(driver: &mut EmbeddedDriver<T>) {
    let handle = driver.add_stream(stream()).unwrap();
    let (mut reader, _lease) = driver
        .recording_reader(handle, Role::Optional)
        .unwrap()
        .into_parts();
    let mut publication = driver.publication(handle).unwrap();
    let most = 5 * usize::try_from(MIN_TERM_LENGTH).unwrap() / MESSAGE;
    assert_eq!(offer_until_refused(driver, &mut publication, most), most);
    let mut out = vec![0u8; usize::try_from(MIN_TERM_LENGTH).unwrap()];
    let from = reader.position();
    assert!(matches!(
        reader.read_committed(from, ReadOrigin::Cursor, &mut out),
        Err(ReadError::Unavailable { .. })
    ));
    let head = reader.rejoin_at_head().unwrap();
    assert!(head > from);
    assert!(matches!(
        publication.offer(&[9; MESSAGE]).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    driver.do_work().unwrap();
    match reader.read_committed(head, ReadOrigin::Cursor, &mut out) {
        Ok(ReadOutcome::Copied { len, .. }) => {
            assert!(len > MESSAGE);
            assert!(out[len - MESSAGE..len].iter().all(|&byte| byte == 9));
        }
        other => panic!("{other:?}"),
    }
}

/// A removed stream stays while a recording reader holds its lease: its
/// conductor positions the seal, the reader ends there, and the stream is
/// freed only once the reader and the lease are dropped.
#[test]
fn a_recording_reader_keeps_a_removed_stream_to_its_seal() {
    keeps_a_removed_stream_to_its_seal(&mut EmbeddedDriver::new().unwrap());
}

fn keeps_a_removed_stream_to_its_seal<T: StreamTerms>(driver: &mut EmbeddedDriver<T>) {
    let handle = driver.add_stream(stream()).unwrap();
    let (mut reader, lease) = driver
        .recording_reader(handle, Role::Required)
        .unwrap()
        .into_parts();
    let mut publication = driver.publication(handle).unwrap();
    assert_eq!(offer_until_refused(driver, &mut publication, 3), 3);
    drop(publication);
    driver.remove_stream(handle).unwrap();
    for _ in 0..4 {
        driver.do_work().unwrap();
    }
    assert!(driver.seal_state(handle).is_ok(), "kept while leased");
    let end = drain(&mut reader);
    assert_eq!(
        reader.seal_position(),
        Some(end),
        "ends at the positioned seal"
    );
    drop(reader);
    driver.do_work().unwrap();
    assert!(
        driver.seal_state(handle).is_ok(),
        "the lease still keeps it"
    );
    drop(lease);
    driver.do_work().unwrap();
    assert!(matches!(
        driver.seal_state(handle),
        Err(DriverError::UnknownStream { .. })
    ));
}

/// Gap 6: a recording's reader is a member of the stream's cutovers. A
/// recorded stream is reconfigured, and once the reader reads to the
/// seal, its link offers it a successor recording cell at the seal's
/// stream position.
#[test]
fn a_recorded_stream_cuts_over_and_offers_the_reader_a_successor() {
    cuts_over_and_offers_a_successor(&mut EmbeddedDriver::new().unwrap());
}

fn cuts_over_and_offers_a_successor<T: StreamTerms>(driver: &mut EmbeddedDriver<T>) {
    use karyos_client::{LinkStatus, Next, Successor};

    let handle = driver.add_stream(stream()).unwrap();
    let reconfiguration = crate::generations::Reconfiguration {
        term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
        spare_slots: 6,
    };
    let recording = driver.recording_reader(handle, Role::Required).unwrap();
    let (link, base) = (Arc::clone(recording.link()), recording.base());
    assert_eq!(base, 0);
    let (mut reader, _lease) = recording.into_parts();
    let mut publication = driver.publication(handle).unwrap();
    assert!(matches!(
        publication.offer(&[3u8; 100]).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    driver.reconfigure_stream(handle, reconfiguration).unwrap();
    assert_eq!(link.status(), LinkStatus::Pending);
    // The writer's release positions the seal; the cutover opens.
    assert_eq!(
        publication.offer(&[4u8; 100]).unwrap(),
        OfferOutcome::AdminAction
    );
    let _ = driver.do_work().unwrap();
    assert_eq!(link.status(), LinkStatus::Offered);
    let seal = driver.generations(handle).unwrap()[0].seal.unwrap();
    // The reader drains to the seal, then moves.
    let mut out = vec![0u8; 4096];
    let next = loop {
        let position = reader.position();
        match reader
            .read_committed(
                position,
                karyos_sys::log_buffer::ReadOrigin::Cursor,
                &mut out,
            )
            .unwrap()
        {
            karyos_sys::log_buffer::ReadOutcome::Copied { next, .. } => {
                reader.sent(next).unwrap();
            }
            karyos_sys::log_buffer::ReadOutcome::Pending => break position,
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(next, seal);
    assert!(reader.sealed_with_successor());
    let Next::Moved {
        base,
        successor: Successor::Recording(successor),
    } = link.next(true)
    else {
        panic!("no successor recording cell");
    };
    assert_eq!(base, seal);
    assert_eq!(successor.position(), 0);
}

/// A required recording of a stream starting at `initial_term_id` reads
/// about four terms; returns the messages accepted and where it read to.
fn record_four_terms(initial_term_id: u32) -> (usize, u64) {
    record_four_terms_on(
        &mut EmbeddedDriver::with_config(crate::embedded::DriverConfig {
            initial_term_id: Some(initial_term_id),
            ..crate::embedded::DriverConfig::default()
        })
        .unwrap(),
    )
}

/// As [`record_four_terms`], on `driver`.
fn record_four_terms_on<T: StreamTerms>(driver: &mut EmbeddedDriver<T>) -> (usize, u64) {
    let handle = driver.add_stream(stream()).unwrap();
    let (mut reader, _lease) = driver
        .recording_reader(handle, Role::Required)
        .unwrap()
        .into_parts();
    let mut publication = driver.publication(handle).unwrap();
    let most = 4 * usize::try_from(MIN_TERM_LENGTH).unwrap() / MESSAGE;
    let mut accepted = 0;
    let mut position = 0;
    while accepted < most {
        accepted += offer_until_refused(driver, &mut publication, most - accepted);
        position = drain(&mut reader);
        driver.do_work().unwrap();
    }
    (accepted, position)
}

/// A required recording of a stream starting just below `u32::MAX` reads
/// across the term id wrap (term ids MAX - 1, MAX, 0 and 1) exactly what
/// it reads from a stream starting at 7 (SPEC §4, initial state).
#[test]
fn a_required_recording_reads_across_the_term_id_wrap() {
    let wrapped = record_four_terms(u32::MAX - 1);
    assert_eq!(wrapped, record_four_terms(7));
    assert!(wrapped.1 > 3 * u64::from(MIN_TERM_LENGTH));
}

/// The same recordings on a shared-terms driver, as `karyosd` runs
/// (quantstratum-docs: karyos/design/archive-host.md, H1): the stream's
/// log lives in a shared region, and the recording reads it there.
#[cfg(target_os = "linux")]
mod shared {
    use karyos_sys::term_bytes::SharedTerms;

    use super::*;
    use crate::admission::IpcConfig;
    use crate::clock::SystemClock;
    use crate::embedded::{DriverConfig, sealed};

    /// A driver whose streams live in shared regions, admitting on a
    /// directory of its own; removed with it.
    struct Ipc {
        driver: EmbeddedDriver<SharedTerms>,
        dir: std::path::PathBuf,
    }

    impl Drop for Ipc {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn ipc(name: &str) -> Ipc {
        ipc_with(name, DriverConfig::default())
    }

    fn ipc_with(name: &str, config: DriverConfig) -> Ipc {
        let dir = std::env::temp_dir().join(format!("karyos-h1-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let timeout = 5_000_000_000;
        let driver = EmbeddedDriver::<SharedTerms>::with_ipc(
            config,
            IpcConfig {
                dir: dir.clone(),
                max_pending_hellos: 2,
                hello_timeout: timeout,
                max_outbound_per_client: 8,
                fetch_deadline: timeout,
                max_exports_per_client: 16,
                max_fetches_per_client: 4,
                max_regions_per_fetch: 4,
                max_fetch_bytes: 1 << 30,
                max_tools: crate::admission::DEFAULT_MAX_TOOLS,
                client_send_buffer: None,
            },
            Box::new(SystemClock::new()),
        )
        .unwrap();
        Ipc { driver, dir }
    }

    /// The recorded stream's log is a shared region, not heap terms.
    #[test]
    fn a_shared_stream_is_recorded_from_its_region() {
        let mut ipc = ipc("region");
        let handle = ipc.driver.add_stream(stream()).unwrap();
        assert!(
            <SharedTerms as sealed::Create>::region(&ipc.driver.stream(handle).unwrap().buffer)
                .is_some()
        );
        let (mut reader, _lease) = ipc
            .driver
            .recording_reader(handle, Role::Required)
            .unwrap()
            .into_parts();
        let mut publication = ipc.driver.publication(handle).unwrap();
        assert_eq!(offer_until_refused(&mut ipc.driver, &mut publication, 3), 3);
        assert!(drain(&mut reader) > 0);
    }

    #[test]
    fn a_required_recording_bounds_a_shared_publisher() {
        required_bounds_the_publisher(&mut ipc("required").driver);
    }

    #[test]
    fn test_recording_required_alone_connects_and_bounds_a_shared_stream_until_it_leaves() {
        required_recording_alone(&mut ipc("alone").driver);
    }

    #[test]
    fn an_optional_recording_of_a_shared_stream_rejoins_at_the_head() {
        optional_is_lapped_and_rejoins(&mut ipc("optional").driver);
    }

    #[test]
    fn a_recording_reader_keeps_a_removed_shared_stream_to_its_seal() {
        keeps_a_removed_stream_to_its_seal(&mut ipc("removed").driver);
    }

    /// A cutover of a shared stream offers its recording a successor
    /// (IMPLEMENT's P3 on #516).
    #[test]
    fn a_recorded_shared_stream_cuts_over_and_offers_a_successor() {
        cuts_over_and_offers_a_successor(&mut ipc("cutover").driver);
    }

    /// A shared stream's recording reads across the term id wrap exactly
    /// what it reads from a stream starting at 7 (IMPLEMENT's P3 on #516).
    #[test]
    fn a_required_recording_of_a_shared_stream_reads_across_the_term_id_wrap() {
        let at = |name, initial_term_id| {
            record_four_terms_on(
                &mut ipc_with(
                    name,
                    DriverConfig {
                        initial_term_id: Some(initial_term_id),
                        ..DriverConfig::default()
                    },
                )
                .driver,
            )
        };
        let wrapped = at("wrap", u32::MAX - 1);
        assert_eq!(wrapped, at("seven", 7));
        assert!(wrapped.1 > 3 * u64::from(MIN_TERM_LENGTH));
    }
}
