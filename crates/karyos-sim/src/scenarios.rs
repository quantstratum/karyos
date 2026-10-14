// SPDX-License-Identifier: Apache-2.0

//! The named scenarios and their seed lists
//! (`quantstratum-docs: karyos/design/simulator-and-bench.md`).

use karyos_sys::log_buffer::PublicationMode;

use crate::sim::{Faults, Scenario, StreamPlan};

/// Seeds each scenario runs under `cargo test`.
pub const DEFAULT_SEEDS: u64 = 40;

fn concurrent(publishers: u8) -> PublicationMode {
    PublicationMode::Concurrent {
        publishers,
        allow_non_lse: true,
    }
}

fn exclusive_plan() -> StreamPlan {
    StreamPlan {
        publication: PublicationMode::Exclusive,
        publishers: 1,
        required: 1,
        optional: 1,
    }
}

fn concurrent_plan() -> StreamPlan {
    StreamPlan {
        publication: concurrent(3),
        publishers: 3,
        required: 1,
        optional: 2,
    }
}

fn scenario(name: &'static str, faults: Faults) -> Scenario {
    Scenario {
        name,
        streams: vec![exclusive_plan(), concurrent_plan()],
        faults,
        steps: 1500,
    }
}

/// Every named scenario.
#[must_use]
pub fn all() -> Vec<Scenario> {
    let none = Faults::default();
    vec![
        scenario("steady", none),
        scenario(
            "pauses",
            Faults {
                pause: true,
                pause_in_claim: true,
                ..none
            },
        ),
        scenario(
            "forgotten",
            Faults {
                forget: true,
                crash: true,
                ..none
            },
        ),
        scenario(
            "removal",
            Faults {
                removal: true,
                pause_in_claim: true,
                ..none
            },
        ),
        scenario(
            "cutover",
            Faults {
                cutover: true,
                pause: true,
                pause_in_claim: true,
                ..none
            },
        ),
        Scenario {
            steps: 3000,
            streams: vec![exclusive_plan(), concurrent_plan(), concurrent_plan()],
            ..scenario(
                "mixed",
                Faults {
                    pause: true,
                    pause_in_claim: true,
                    forget: true,
                    crash: true,
                    removal: true,
                    cutover: true,
                },
            )
        },
    ]
}

/// The seeds to run: `KARYOS_SIM_SEED` replays one, `KARYOS_SIM_SEEDS`
/// widens the sweep, otherwise [`DEFAULT_SEEDS`] from 1.
#[must_use]
pub fn seeds() -> Vec<u64> {
    if let Some(seed) = std::env::var("KARYOS_SIM_SEED")
        .ok()
        .and_then(|value| value.parse().ok())
    {
        return vec![seed];
    }
    let count = std::env::var("KARYOS_SIM_SEEDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_SEEDS);
    (1..=count).collect()
}
