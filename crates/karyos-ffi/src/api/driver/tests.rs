// SPDX-License-Identifier: Apache-2.0

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::*;
use crate::api::client;

/// Serializes these tests with every other test that opens drivers:
/// together they would open more drivers at once than the table holds
/// ([`MAX_DRIVERS`]), and some of them fill it (karyos#993).
fn serial() -> crate::test_drivers::Permit {
    crate::test_drivers::all_drivers()
}

fn created() -> Handle {
    create(&Options::defaults()).unwrap()
}

/// A stream of `stream_id` with the defaults otherwise.
fn stream(stream_id: i32) -> StreamOptions {
    StreamOptions {
        stream_id,
        ..StreamOptions::defaults()
    }
}

const YIELD: Idle = Idle {
    strategy: IDLE_YIELD,
    sleep_ns: 0,
};

#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_driver_is_driven_by_its_caller_then_by_its_thread() {
    let _serial = serial();
    let driver = created();
    assert!(do_work(driver).is_ok());
    assert_eq!(stop(driver), Err(Status::Busy));
    start(driver, YIELD).unwrap();
    // Its thread drives it: the caller may not, and it starts once.
    assert_eq!(do_work(driver), Err(Status::Busy.into()));
    assert_eq!(start(driver, YIELD), Err(Status::Busy.into()));
    stop(driver).unwrap();
    assert!(do_work(driver).is_ok());
    close(driver).unwrap();
    assert_eq!(do_work(driver), Err(Status::Closed.into()));
    assert_eq!(close(driver), Err(Status::Closed));
}

#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_driver_closes_with_its_thread_running() {
    let _serial = serial();
    let driver = created();
    start(
        driver,
        Idle {
            strategy: IDLE_SLEEP,
            sleep_ns: 1_000,
        },
    )
    .unwrap();
    close(driver).unwrap();
    assert_eq!(stop(driver), Err(Status::Closed));
}

/// `KARYOS_IDLE_YIELD_THEN_SLEEP` (ADR-0066) runs the thread with the
/// agents' own strategy: the thread starts, idles past its 64 yields into
/// its sleeps, and stops.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_driver_thread_runs_with_yield_then_sleep() {
    let _serial = serial();
    let driver = created();
    start(
        driver,
        Idle {
            strategy: IDLE_YIELD_THEN_SLEEP,
            sleep_ns: 0,
        },
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    stop(driver).unwrap();
    assert!(do_work(driver).is_ok());
    close(driver).unwrap();
}

#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn an_unknown_idle_strategy_or_configuration_is_refused() {
    let _serial = serial();
    let driver = created();
    assert_eq!(
        start(
            driver,
            Idle {
                strategy: 4,
                sleep_ns: 0
            }
        ),
        Err(Status::InvalidArgument.into())
    );
    close(driver).unwrap();
    let options = Options {
        ring_capacity: 1000,
        ..Options::defaults()
    };
    assert_eq!(create(&options), Err(Status::InvalidArgument.into()));
}

/// A lane above `max_stream_bytes` (karyos#809) reaches a C host as the
/// caller's argument with its bytes and the cap, not as an unknown error.
/// `abi::tests::a_stream_above_the_options_cap_is_refused_with_its_bytes_and_the_cap`
/// covers it through `karyos_driver_options.max_stream_bytes` (karyos#818).
#[test]
fn a_stream_above_the_cap_is_an_invalid_argument_with_its_bytes_and_the_cap() {
    let failure = Failure::from(&DriverError::StreamTooLarge {
        bytes: 3 << 20,
        max: 1 << 20,
    });
    assert_eq!(
        failure,
        Failure::with(Status::InvalidArgument, 3 << 20, 1 << 20)
    );
}

#[test]
fn the_defaults_are_the_drivers() {
    let _serial = serial();
    let config = Options::defaults().config().unwrap();
    assert_eq!(config, DriverConfig::default());
}

#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_client_follows_its_driver_to_the_close() {
    let _serial = serial();
    let driver = created();
    let client = client::connect_embedded(driver).unwrap();
    assert!(client::poll(client).is_ok());
    assert!(do_work(driver).is_ok());
    close(driver).unwrap();
    assert_eq!(client::poll(client), Err(Status::Closed));
    // Its handle stays to be closed.
    client::close(client).unwrap();
    assert_eq!(client::connect_embedded(driver), Err(Status::Closed.into()));
}

#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_panic_in_a_called_duty_cycle_poisons_the_driver_and_its_clients() {
    let _serial = serial();
    let driver = created();
    let client = client::connect_embedded(driver).unwrap();
    // A panic in any call that holds the driver's slot, as a duty cycle
    // does.
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        with_slot(driver, |_| {
            std::panic::resume_unwind(Box::new("in a duty cycle"))
        })
        .unwrap();
    }));
    assert!(unwound.is_err());
    assert_eq!(do_work(driver), Err(Status::Internal.into()));
    assert_eq!(client::poll(client), Err(Status::Internal));
    // Close still releases both.
    client::close(client).unwrap();
    close(driver).unwrap();
}

#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_panic_on_the_drivers_thread_poisons_it_and_its_clients() {
    let _serial = serial();
    let driver = created();
    let client = client::connect_embedded(driver).unwrap();
    start(driver, YIELD).unwrap();
    // Poison the driver the thread shares, as a panic in its duty cycle
    // does.
    drivers()
        .with(driver, |slot| {
            let Mode::Threaded(threaded) = &slot.mode else {
                panic!("not threaded");
            };
            let shared = Arc::clone(&threaded.shared);
            let poisoner = std::thread::spawn(move || {
                let _held = shared.lock();
                std::panic::resume_unwind(Box::new("on the driver's thread"));
            });
            assert!(poisoner.join().is_err());
        })
        .unwrap();
    assert_eq!(do_work(driver), Err(Status::Internal.into()));
    // The driver's thread marks it lost when it next finds it poisoned.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while client::poll(client) != Err(Status::Internal) {
        assert!(
            std::time::Instant::now() < deadline,
            "the client never saw it"
        );
        std::thread::yield_now();
    }
    assert_eq!(
        client::connect_embedded(driver),
        Err(Status::Internal.into())
    );
    // Stopping finds it poisoned; it stays lost until closed.
    assert_eq!(stop(driver), Err(Status::Internal));
    assert_eq!(start(driver, YIELD), Err(Status::Internal.into()));
    assert_eq!(do_work(driver), Err(Status::Internal.into()));
    client::close(client).unwrap();
    close(driver).unwrap();
}

#[test]
fn driver_errors_map_to_statuses() {
    let _serial = serial();
    let cases = [
        (DriverError::InvalidConfig, Status::InvalidArgument),
        (DriverError::TooManyClients, Status::ResourcesUnavailable),
        (
            DriverError::ClientIdsExhausted,
            Status::ResourcesUnavailable,
        ),
        (DriverError::Terminal, Status::Closed),
        (DriverError::NotAdmitting, Status::Refused),
        (DriverError::TooManyStreams, Status::ResourcesUnavailable),
        (
            DriverError::StreamIdsExhausted,
            Status::ResourcesUnavailable,
        ),
        (DriverError::NetworkBusy, Status::Unknown),
    ];
    for (error, status) in cases {
        assert_eq!(Failure::from(&error).status, status, "{error:?}");
    }
    let limit = DriverError::DescriptorLimit {
        needed: 300,
        limit: 256,
        hard: None,
    };
    assert_eq!(
        Failure::from(&limit),
        Failure::with(Status::System, 300, 256)
    );
    // A schedule the buffer refuses is an invalid argument, not SYSTEM.
    let capacity = DriverError::Sys(ScheduleError::Capacity { capacity: 3 }.into());
    assert_eq!(
        Failure::from(&capacity),
        Failure::with(Status::InvalidArgument, 3, 0)
    );
    let mode = DriverError::Sys(SysError::InvalidPublicationMode { reason: "GC-7" });
    assert_eq!(Failure::from(&mode).status, Status::InvalidArgument);
}

#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn the_clients_of_a_full_driver_are_refused() {
    let _serial = serial();
    let options = Options {
        max_clients: 1,
        ..Options::defaults()
    };
    let driver = create(&options).unwrap();
    let first = client::connect_embedded(driver).unwrap();
    assert_eq!(
        client::connect_embedded(driver),
        Err(Status::ResourcesUnavailable.into())
    );
    client::close(first).unwrap();
    close(driver).unwrap();
}

#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_publication_follows_its_clients_driver() {
    let _serial = serial();
    use crate::api::publication;
    let driver = created();
    add_stream(driver, &stream(7)).unwrap();
    let client = client::connect_embedded(driver).unwrap();
    // The driver's thread serves the control call.
    start(driver, YIELD).unwrap();
    let opened = publication::add(client, "karyos:ipc", 7, false).unwrap();
    assert_ne!(
        publication::offer(opened, 0, b"x"),
        Err(Status::Closed.into())
    );
    close(driver).unwrap();
    assert_eq!(
        publication::offer(opened, 0, b"x"),
        Err(Status::Closed.into())
    );
    assert_eq!(
        publication::claim(opened, 0, 1).map(|(handle, _)| handle),
        Err(Status::Closed.into())
    );
    assert_eq!(
        publication::add(client, "karyos:ipc", 8, false),
        Err(Status::Closed.into())
    );
    // The client's close closes it.
    client::close(client).unwrap();
    assert_eq!(
        publication::offer(opened, 0, b"x"),
        Err(Status::Closed.into())
    );
}

#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_stream_is_added_once_and_removed_once() {
    let _serial = serial();
    let driver = created();
    add_stream(driver, &stream(11)).unwrap();
    assert_eq!(
        add_stream(driver, &stream(11)),
        Err(Failure::with(Status::InvalidArgument, 11, 1))
    );
    // The C ABI keys streams by stream id: another session of it is
    // refused too, naming the session it has.
    let other_session = StreamOptions {
        session_id: 2,
        ..stream(11)
    };
    assert_eq!(
        add_stream(driver, &other_session),
        Err(Failure::with(Status::InvalidArgument, 11, 1))
    );
    remove_stream(driver, 11).unwrap();
    assert_eq!(
        remove_stream(driver, 11),
        Err(Failure::with(Status::InvalidArgument, 11, 0))
    );
    // A removed stream retires in the driver: its id stays taken.
    assert_eq!(
        add_stream(driver, &stream(11)).map_err(|failure| failure.status),
        Err(Status::InvalidArgument)
    );
    close(driver).unwrap();
    assert_eq!(add_stream(driver, &stream(12)), Err(Status::Closed.into()));
}

#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn stream_options_this_version_does_not_take_are_refused() {
    let _serial = serial();
    let driver = created();
    let refused = [
        (
            StreamOptions {
                lane: 1,
                ..stream(1)
            },
            Status::InvalidLane,
        ),
        (
            StreamOptions {
                publication_mode: 1,
                ..stream(1)
            },
            Status::InvalidArgument,
        ),
        (
            StreamOptions {
                allow_unconnected: 2,
                ..stream(1)
            },
            Status::InvalidArgument,
        ),
        (
            StreamOptions {
                on_required_loss: 3,
                ..stream(1)
            },
            Status::InvalidArgument,
        ),
        (
            StreamOptions {
                term_length: 1000,
                ..stream(1)
            },
            Status::InvalidArgument,
        ),
        (
            StreamOptions {
                spare_slots: 256,
                ..stream(1)
            },
            Status::InvalidArgument,
        ),
        // A schedule ring the driver refuses (TT-1, GC-7) is an invalid
        // argument, not a system failure.
        (
            StreamOptions {
                schedule_capacity: 3,
                ..stream(1)
            },
            Status::InvalidArgument,
        ),
        (
            StreamOptions {
                schedule_capacity: MAX_CAPACITY * 2,
                ..stream(1)
            },
            Status::InvalidArgument,
        ),
        (
            StreamOptions {
                schedule_capacity: 4,
                publication_mode: PUBLICATION_CONCURRENT,
                publishers: 1,
                ..stream(1)
            },
            Status::InvalidArgument,
        ),
    ];
    for (options, status) in refused {
        assert_eq!(
            add_stream(driver, &options).map_err(|failure| failure.status),
            Err(status),
            "{options:?}"
        );
    }
    // Each loss policy the driver has is taken.
    for (stream_id, loss) in [(2, LOSS_HOLD), (3, LOSS_CONTINUE), (4, LOSS_ABORT)] {
        let options = StreamOptions {
            on_required_loss: loss,
            ..stream(stream_id)
        };
        add_stream(driver, &options).unwrap();
    }
    // Any schedule ring, a valid capacity included, is an invalid argument
    // on a driver stream: nothing would release it (owner item 65).
    let timed = StreamOptions {
        schedule_capacity: 4,
        ..stream(5)
    };
    assert_eq!(
        add_stream(driver, &timed).map_err(|failure| failure.status),
        Err(Status::InvalidArgument)
    );
    close(driver).unwrap();
}

#[test]
fn the_stream_defaults_are_a_valid_heap_stream() {
    let _serial = serial();
    let config = StreamOptions::defaults().config().unwrap();
    assert_eq!(config.buffer.term_length.get(), MIN_TERM_LENGTH);
    assert_eq!(config.buffer.publication, PublicationMode::Exclusive);
    assert_eq!(config.on_required_loss, LossPolicy::Hold);
    assert!(!config.allow_unconnected);
    assert!(config.conflation.is_none());
}

#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_subscription_follows_its_clients_driver() {
    use crate::api::subscription;
    let _serial = serial();
    let driver = created();
    add_stream(driver, &stream(17)).unwrap();
    let client = client::connect_embedded(driver).unwrap();
    // The driver's thread serves the control call.
    start(driver, YIELD).unwrap();
    let opened = subscription::add(client, "karyos:ipc", 17).unwrap();
    let mut ignore = |_: &[u8], _: &karyos_client::MessageInfo| {};
    assert!(subscription::poll(opened, 1, &mut ignore).is_ok());
    close(driver).unwrap();
    assert_eq!(
        subscription::poll(opened, 1, &mut ignore).map_err(|(failure, _)| failure.status),
        Err(Status::Closed)
    );
    assert_eq!(
        subscription::add(client, "karyos:ipc", 17).map_err(|failure| failure.status),
        Err(Status::Closed)
    );
    client::close(client).unwrap();
}

/// A stop or a close of a started driver returns at once whatever its idle
/// strategy, a sleep of `u64::MAX` nanoseconds included: the thread parks
/// in its idle sleep and the stop unparks it (`karyos.h`, Threads). A
/// driver call meanwhile takes the driver at once too: the thread parks
/// with the driver's lock released.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn no_idle_strategy_holds_a_stop_or_a_close() {
    let _serial = serial();
    let bound = std::time::Duration::from_secs(1);
    for strategy in [
        IDLE_SLEEP,
        IDLE_YIELD_THEN_SLEEP,
        IDLE_YIELD,
        IDLE_BUSY_SPIN,
    ] {
        let idle = Idle {
            strategy,
            sleep_ns: if strategy == IDLE_SLEEP { u64::MAX } else { 0 },
        };
        for closing in [false, true] {
            let driver = created();
            start(driver, idle).unwrap();
            // The thread runs a cycle and goes idle: no stream, no work.
            std::thread::sleep(std::time::Duration::from_millis(50));
            let (done, returned) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let result =
                    add_stream(driver, &stream(900)).and_then(|()| remove_stream(driver, 900));
                let _ = done.send(result);
            });
            let result = returned.recv_timeout(bound).unwrap_or_else(|_| {
                panic!("strategy {strategy}: a driver call waited past {bound:?}")
            });
            assert_eq!(result, Ok(()), "strategy {strategy}: a driver call");
            // Off this thread, so a stop that never returns fails the
            // test instead of hanging it.
            let (done, returned) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let result = if closing { close(driver) } else { stop(driver) };
                let _ = done.send(result);
            });
            let result = returned.recv_timeout(bound).unwrap_or_else(|_| {
                panic!(
                    "strategy {strategy}: the {} waited past {bound:?}",
                    if closing { "close" } else { "stop" }
                )
            });
            assert_eq!(result, Ok(()), "strategy {strategy}");
            if !closing {
                close(driver).unwrap();
            }
        }
    }
}

/// A call on a started driver waits for about one duty cycle, not for as
/// long as the thread keeps winning the driver's lock (`karyos.h`,
/// "Threads"). Against a busy-spinning thread, which takes the lock back
/// at once after each cycle, 32 adds and removes of streams each wait
/// through at most the cycle in progress and the one that may start
/// before the thread sees the call's announcement. The count starts at
/// the announcement and is the thread's own, not a clock, so a loaded
/// machine cannot fail it: a caller preempted before it announces itself
/// counts none of the cycles run meanwhile.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_call_on_a_busy_spinning_driver_waits_for_one_cycle() {
    let _serial = serial();
    let driver = created();
    start(
        driver,
        Idle {
            strategy: IDLE_BUSY_SPIN,
            sleep_ns: 0,
        },
    )
    .unwrap();
    let cycles = || {
        drivers()
            .with(driver, |slot| match &slot.mode {
                Mode::Threaded(threaded) => (
                    threaded.cycles.done.load(Ordering::Acquire),
                    threaded.cycles.most.load(Ordering::Acquire),
                ),
                _ => panic!("not started"),
            })
            .unwrap()
    };
    // The thread is spinning before the first call: on a loaded machine it
    // may not have run yet.
    let begun = std::time::Instant::now();
    while cycles().0 == 0 {
        assert!(
            begun.elapsed() < std::time::Duration::from_secs(60),
            "the thread never ran"
        );
        std::thread::yield_now();
    }
    for id in 1000..1032 {
        add_stream(driver, &stream(id)).unwrap();
        remove_stream(driver, id).unwrap();
    }
    let (done, most) = cycles();
    close(driver).unwrap();
    assert!(
        most <= 2,
        "a call waited through {most} cycles ({done} in all)"
    );
}
