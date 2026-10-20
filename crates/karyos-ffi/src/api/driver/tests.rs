// SPDX-License-Identifier: Apache-2.0

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::*;
use crate::api::client;

fn created() -> Handle {
    create(&Options::defaults()).unwrap()
}

const YIELD: Idle = Idle {
    strategy: IDLE_YIELD,
    sleep_ns: 0,
};

#[test]
fn a_driver_is_driven_by_its_caller_then_by_its_thread() {
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
fn a_driver_closes_with_its_thread_running() {
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

#[test]
fn an_unknown_idle_strategy_or_configuration_is_refused() {
    let driver = created();
    assert_eq!(
        start(
            driver,
            Idle {
                strategy: 3,
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

#[test]
fn the_defaults_are_the_drivers() {
    let config = Options::defaults().config().unwrap();
    assert_eq!(config, DriverConfig::default());
}

#[test]
fn a_client_follows_its_driver_to_the_close() {
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
fn a_panic_in_a_called_duty_cycle_poisons_the_driver_and_its_clients() {
    let driver = created();
    let client = client::connect_embedded(driver).unwrap();
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        drivers()
            .with(driver, |_| {
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
fn a_panic_on_the_drivers_thread_poisons_it_and_its_clients() {
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
    assert_eq!(client::poll(client), Err(Status::Internal));
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
    let cases = [
        (DriverError::InvalidConfig, Status::InvalidArgument),
        (DriverError::TooManyClients, Status::ResourcesUnavailable),
        (
            DriverError::ClientIdsExhausted,
            Status::ResourcesUnavailable,
        ),
        (DriverError::Terminal, Status::Closed),
        (DriverError::NotAdmitting, Status::Refused),
        (DriverError::TooManyStreams, Status::Unknown),
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
}

#[test]
fn the_clients_of_a_full_driver_are_refused() {
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
