// SPDX-License-Identifier: Apache-2.0

//! The named scenarios and their seed lists
//! (`quantstratum-docs: karyos/design/simulator-and-bench.md`).

use karyos_driver::LossPolicy;
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
        clients: 0,
    }
}

fn concurrent_plan() -> StreamPlan {
    StreamPlan {
        publication: concurrent(3),
        publishers: 3,
        required: 1,
        optional: 2,
        clients: 0,
    }
}

fn scenario(name: &'static str, faults: Faults) -> Scenario {
    Scenario {
        name,
        streams: vec![exclusive_plan(), concurrent_plan()],
        faults,
        on_required_loss: LossPolicy::Hold,
        steps: 1500,
    }
}

/// A client's heartbeat stops while the driver's clock advances, under
/// `policy` (`quantstratum-docs: karyos/design/required-participant-loss.md`,
/// Simulator): each stream has an in-process required reader and one
/// behind a client that can stall, also while it holds a loan. Under
/// `continue` a required reader takes a spare-slot credit like an optional
/// one, so the concurrent stream keeps one optional reader: three
/// publishers and three readers spend the six credits.
fn stall(name: &'static str, policy: LossPolicy) -> Scenario {
    let concurrent = StreamPlan {
        optional: 1,
        clients: 1,
        ..concurrent_plan()
    };
    Scenario {
        name,
        streams: vec![
            StreamPlan {
                clients: 1,
                ..exclusive_plan()
            },
            concurrent,
        ],
        faults: Faults {
            stall: true,
            pause: true,
            pause_in_claim: true,
            ..Faults::default()
        },
        on_required_loss: policy,
        steps: 3000,
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
                    stall: false,
                },
            )
        },
        stall("stall-hold", LossPolicy::Hold),
        stall("stall-continue", LossPolicy::Continue),
        stall("stall-abort", LossPolicy::Abort),
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
