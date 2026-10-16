// SPDX-License-Identifier: Apache-2.0

//! The DRR state machine against a model of lanes (`quantstratum-docs:
//! karyos/design/aggregate-lanes.md`, "Acceptance evidence"). Each rule a
//! test checks also has a negative control: the same test with the rule
//! removed (`Faults`) must fail its property.

use std::collections::VecDeque;

use proptest::prelude::*;

use super::*;

/// Lanes whose heads are the fronts of queues of charges; a closed lane
/// is ineligible whatever it holds. Served frames are logged in order.
#[derive(Debug, Clone, Default)]
struct Model {
    queues: [VecDeque<u64>; MAX_LANES],
    closed: [bool; MAX_LANES],
    /// Service attempts of each lane that fail before one succeeds.
    failures: [u32; MAX_LANES],
    /// A lane refilled with this charge whenever it empties.
    saturate: [Option<u64>; MAX_LANES],
    log: Vec<(usize, u64)>,
}

impl Model {
    fn with(queues: &[&[u64]]) -> Self {
        let mut model = Self::default();
        for (queue, charges) in model.queues.iter_mut().zip(queues) {
            queue.extend(charges.iter().copied());
        }
        model
    }

    fn refill(&mut self, lane: usize) {
        if let Some(charge) = self.saturate[lane]
            && self.queues[lane].is_empty()
        {
            self.queues[lane].push_back(charge);
        }
    }
}

impl LaneSource for Model {
    fn probe(&mut self, lane: usize) -> Probe {
        self.refill(lane);
        match self.queues[lane].front() {
            Some(&charge) if !self.closed[lane] => Probe::Eligible { charge },
            _ => Probe::Ineligible,
        }
    }

    fn serve(&mut self, lane: usize) -> Service {
        if self.failures[lane] > 0 {
            self.failures[lane] -= 1;
            return Service::NotServed;
        }
        let charge = self.queues[lane].pop_front().unwrap();
        self.log.push((lane, charge));
        Service::Served
    }
}

/// Totals over calls, per lane.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Totals {
    served: [u64; MAX_LANES],
    frames: [u64; MAX_LANES],
    credits: [u64; MAX_LANES],
    forfeited: [u64; MAX_LANES],
}

impl Totals {
    fn add(&mut self, report: &Report) {
        for (lane, entry) in report.lanes.iter().enumerate() {
            self.served[lane] += entry.served_bytes;
            self.frames[lane] += entry.served_frames;
            self.credits[lane] += entry.credits;
            self.forfeited[lane] += entry.forfeited;
        }
    }
}

const ALL: Budget = Budget {
    work: u32::MAX,
    bytes: u64::MAX,
};

fn drr(quanta: &[u64], max_charge: u64) -> Drr {
    Drr::new(DrrConfig::new(quanta, max_charge).unwrap())
}

/// Credits equal service, forfeits and the deficit held, per lane.
fn conserved(drr: &Drr, totals: &Totals) -> bool {
    (0..drr.config().lanes()).all(|lane| {
        let quantum = drr.config().quantum(lane).unwrap();
        totals.credits[lane] * quantum
            == totals.served[lane] + totals.forfeited[lane] + drr.deficit(lane).unwrap()
    })
}

#[test]
fn configuration_is_checked() {
    assert_eq!(DrrConfig::new(&[], 10), Err(DrrError::InvalidConfig));
    assert_eq!(DrrConfig::new(&[10; 5], 10), Err(DrrError::InvalidConfig));
    assert_eq!(DrrConfig::new(&[10], 0), Err(DrrError::InvalidConfig));
    assert_eq!(DrrConfig::new(&[10, 9], 10), Err(DrrError::InvalidConfig));
    assert_eq!(DrrConfig::new(&[u64::MAX], 1), Err(DrrError::InvalidConfig));
    let config = DrrConfig::new(&[u64::MAX - 1, 1], 1).unwrap();
    assert_eq!(config.lanes(), 2);
    assert_eq!(config.quantum(1), Some(1));
    assert_eq!(config.quantum(2), None);
    assert_eq!(config.max_charge(), 1);
}

/// A zero budget changes nothing; a byte budget below the head's charge
/// suspends at once without credit, however often it is offered, so it
/// cannot spin or add credit.
#[test]
fn zero_and_too_small_budgets_make_no_progress() {
    let mut drr = drr(&[100, 100], 100);
    let mut model = Model::with(&[&[60, 60], &[60]]);
    let report = drr.run(
        Budget {
            work: 0,
            bytes: 1_000,
        },
        &mut model,
    );
    assert_eq!(report.stop, Stop::WorkExhausted);
    assert_eq!(report.lanes, [LaneReport::default(); MAX_LANES]);
    for _ in 0..10 {
        let report = drr.run(Budget { work: 5, bytes: 59 }, &mut model);
        assert_eq!(
            report.stop,
            Stop::BytesLimited {
                lane: 0,
                charge: 60
            }
        );
        assert_eq!(report.lanes[0], LaneReport::default());
        assert_eq!(
            (drr.cursor(), drr.in_visit(), drr.deficit(0)),
            (0, false, Some(0))
        );
    }
    assert!(model.log.is_empty());
}

/// A budget with work but no bytes suspends before any probe: even with
/// only ineligible lanes, nothing is forfeited, the cursor stays and no
/// round is counted.
#[test]
fn a_zero_byte_budget_changes_nothing() {
    let mut drr = drr_with_residual();
    let mut model = Model {
        closed: [true; MAX_LANES],
        ..Model::default()
    };
    let report = drr.run(Budget { work: 5, bytes: 0 }, &mut model);
    assert_eq!(report.stop, Stop::BytesExhausted);
    assert_eq!(report.rounds, 0);
    assert_eq!(report.lanes, [LaneReport::default(); MAX_LANES]);
    assert_eq!(
        (drr.cursor(), drr.in_visit(), drr.deficit(0)),
        (1, false, Some(400))
    );
}

/// A failed step keeps the report of the steps before it: the frame
/// lane 0 served is counted when lane 1's head turns out invalid.
#[test]
fn a_failed_step_keeps_the_report_of_earlier_steps() {
    let mut drr = drr(&[100, 100], 100);
    let mut model = Model::with(&[&[80], &[0]]);
    let report = drr.run(ALL, &mut model);
    assert_eq!(
        report.stop,
        Stop::Failed(DrrError::InvalidCharge {
            lane: 1,
            charge: 0,
            max: 100
        })
    );
    assert_eq!(report.lanes[0].served_bytes, 80);
    assert_eq!(report.lanes[0].served_frames, 1);
    assert_eq!(report.lanes[1], LaneReport::default());
    assert_eq!(model.log, vec![(0, 80)]);
}

/// A head charged zero or above the maximum is a typed error, with no
/// credit given for it.
#[test]
fn an_invalid_charge_is_a_typed_error() {
    for charge in [0, 101] {
        let mut drr = drr(&[100], 100);
        let mut model = Model::with(&[&[charge]]);
        assert_eq!(
            drr.run(ALL, &mut model).stop,
            Stop::Failed(DrrError::InvalidCharge {
                lane: 0,
                charge,
                max: 100
            })
        );
        assert_eq!((drr.in_visit(), drr.deficit(0)), (false, Some(0)));
    }
}

/// A residual smaller than the next head carries into the lane's next
/// visit; a lane with nothing eligible forfeits it, and a reopened lane
/// starts from a fresh quantum.
#[test]
fn a_residual_carries_and_ineligibility_forfeits_it() {
    let mut drr = drr(&[1_000, 1_000], 1_000);
    let mut model = Model::with(&[&[600, 600, 600], &[]]);
    let report = drr.run(ALL, &mut model);
    // Visit 1: 1000 credited, one 600 served, 400 left < 600: carried.
    // Lane 1 is empty. Visit 2: 400 + 1000, two served, 200 left; then
    // nothing eligible anywhere.
    assert_eq!(model.log, vec![(0, 600), (0, 600), (0, 600)]);
    assert_eq!(report.stop, Stop::Idle);
    assert_eq!(report.lanes[0].credits, 2);
    // The final pass found lane 0 empty: its 200 were forfeited.
    assert_eq!(report.lanes[0].forfeited, 200);
    assert_eq!(drr.deficit(0), Some(0));

    let mut drr = drr_with_residual();
    let mut model = Model::with(&[&[600], &[]]);
    model.closed[0] = true;
    // Lane 1 (empty) first, then lane 0, closed: its 400 are forfeited.
    let report = drr.run(
        Budget {
            work: 2,
            bytes: u64::MAX,
        },
        &mut model,
    );
    assert_eq!(report.lanes[0].forfeited, 400);
    assert_eq!(drr.deficit(0), Some(0));
}

/// A scheduler left with a residual of 400 on lane 0, cursor on lane 1.
fn drr_with_residual() -> Drr {
    let mut drr = drr(&[1_000, 1_000], 1_000);
    let mut model = Model::with(&[&[600, 600], &[]]);
    let _ = drr.run(
        Budget {
            work: 2,
            bytes: u64::MAX,
        },
        &mut model,
    );
    assert_eq!((drr.deficit(0), drr.cursor()), (Some(400), 1));
    drr
}

/// A failed attempt costs work, not deficit or bytes: the head is served
/// at the next attempt and debited once.
#[test]
fn a_failed_attempt_is_not_debited() {
    let mut drr = drr(&[100], 100);
    let mut model = Model::with(&[&[80]]);
    model.failures[0] = 2;
    let report = drr.run(Budget { work: 2, bytes: 80 }, &mut model);
    assert_eq!(report.lanes[0].failed, 2);
    assert_eq!(report.lanes[0].served_bytes, 0);
    assert_eq!(drr.deficit(0), Some(100));
    let report = drr.run(Budget { work: 1, bytes: 80 }, &mut model);
    assert_eq!(report.lanes[0].served_bytes, 80);
    // Resumed: no second quantum.
    assert_eq!(report.lanes[0].credits, 0);
    assert_eq!(drr.deficit(0), Some(20));
}

/// Finite queues on four lanes, with unequal quanta and charges.
fn split_scenario() -> Model {
    Model::with(&[
        &[64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64],
        &[700, 300, 1_200, 50],
        &[1_500, 1_500, 1_500],
        &[200, 200, 200, 200, 1_000],
    ])
}

/// Serves the scenario to the end with `budgets` repeated, under
/// `faults`; returns the order of service (what was served, if a removed
/// rule keeps it from draining).
fn serve_split(budgets: &[Budget], faults: Faults) -> Vec<(usize, u64)> {
    let mut drr = drr(&[1_500, 1_600, 1_500, 2_000], 1_500);
    drr.faults = faults;
    let mut model = split_scenario();
    for budget in budgets.iter().cycle().take(10_000) {
        if drr.run(*budget, &mut model).stop == Stop::Idle {
            break;
        }
    }
    model.log
}

/// Splitting the round across many calls changes nothing: one-step calls
/// and byte-limited calls serve in the order of one unbounded call (no
/// extra quantum, no restart at lane 0, no deficit lost to a suspension).
/// Negative controls: each removed rule changes the order.
#[test]
fn a_round_split_across_calls_serves_in_the_same_order() {
    let whole = serve_split(&[ALL], Faults::default());
    assert_eq!(whole.len(), 24);
    let one_step = [Budget {
        work: 1,
        bytes: u64::MAX,
    }];
    let bytes = [
        Budget {
            work: 10,
            bytes: 100,
        },
        Budget {
            work: 10,
            bytes: 1_500,
        },
        Budget { work: 2, bytes: 63 },
        Budget {
            work: 7,
            bytes: 2_000,
        },
    ];
    for budgets in [&one_step[..], &bytes[..]] {
        assert_eq!(
            serve_split(budgets, Faults::default()),
            whole,
            "{budgets:?}"
        );
    }
    for (name, faults) in [
        (
            "credit on resume",
            Faults {
                credit_on_resume: true,
                ..Faults::default()
            },
        ),
        (
            "restart at lane 0",
            Faults {
                restart_cursor: true,
                ..Faults::default()
            },
        ),
        (
            "reset on budget",
            Faults {
                reset_on_budget: true,
                ..Faults::default()
            },
        ),
    ] {
        assert!(
            [&one_step[..], &bytes[..]]
                .iter()
                .any(|budgets| serve_split(budgets, faults) != whole),
            "the negative control {name} was not detected"
        );
    }
}

/// Lane 0 saturated with small frames and lane 3 with frames of the
/// maximum charge, both always eligible, under budgets that suspend
/// visits mid-way: after `k` credits lane 3 has been served at least
/// `k * Q_3 - F_max` bytes whenever it is between visits, and every visit
/// serves its first head. Returns whether the bound always held, and the
/// credits lane 3 received.
fn lane_three_keeps_its_share(faults: Faults) -> (bool, u64) {
    const F_MAX: u64 = 1_500;
    let quanta = [4_000, 1_500, 1_500, 2_000];
    let mut drr = drr(&quanta, F_MAX);
    drr.faults = faults;
    let mut model = Model::default();
    model.saturate[0] = Some(64);
    model.saturate[3] = Some(F_MAX);
    let budgets = [
        Budget {
            work: 3,
            bytes: 5_000,
        },
        Budget {
            work: 50,
            bytes: 1_600,
        },
        Budget {
            work: 1,
            bytes: u64::MAX,
        },
        Budget {
            work: 9,
            bytes: 3_100,
        },
    ];
    let mut totals = Totals::default();
    for budget in budgets.iter().cycle().take(4_000) {
        let report = drr.run(*budget, &mut model);
        totals.add(&report);
        let between_visits = drr.cursor() != 3 || !drr.in_visit();
        if between_visits {
            let bound = (totals.credits[3] * quanta[3]).saturating_sub(F_MAX);
            if totals.served[3] < bound || totals.frames[3] < totals.credits[3] {
                return (false, totals.credits[3]);
            }
        }
    }
    (true, totals.credits[3])
}

/// The `k * Q - F_max` row; negative control: a suspension that resets
/// the deficit breaks the bound for the lowest lane.
#[test]
fn a_saturated_lane_keeps_k_quanta_less_one_frame() {
    let (held, credits) = lane_three_keeps_its_share(Faults::default());
    assert!(held);
    assert!(credits > 100, "{credits}");
    assert!(
        !lane_three_keeps_its_share(Faults {
            reset_on_budget: true,
            ..Faults::default()
        })
        .0
    );
}

/// A lane closed while it holds a residual forfeits it; while closed it
/// gains no credit, and on reopening it is credited from zero.
#[test]
fn a_blocked_lane_gains_nothing_and_restarts_from_zero() {
    let mut drr = drr(&[1_000, 1_000], 1_000);
    let mut model = Model::default();
    model.saturate[0] = Some(600);
    model.saturate[1] = Some(100);
    let mut totals = Totals::default();
    totals.add(&drr.run(
        Budget {
            work: 4,
            bytes: u64::MAX,
        },
        &mut model,
    ));
    // Lane 0 served 600, carried 400; lane 1 is mid-visit.
    model.closed[0] = true;
    let before = totals.credits[0];
    for _ in 0..20 {
        totals.add(&drr.run(
            Budget {
                work: 7,
                bytes: u64::MAX,
            },
            &mut model,
        ));
    }
    assert_eq!(totals.credits[0], before);
    assert_eq!(totals.forfeited[0], 400);
    assert_eq!(drr.deficit(0), Some(0));
    model.closed[0] = false;
    while drr.cursor() != 0 {
        totals.add(&drr.run(
            Budget {
                work: 1,
                bytes: u64::MAX,
            },
            &mut model,
        ));
    }
    totals.add(&drr.run(
        Budget {
            work: 1,
            bytes: u64::MAX,
        },
        &mut model,
    ));
    assert_eq!(drr.deficit(0), Some(400));
    assert!(conserved(&drr, &totals));
}

/// A step of a generated scenario.
#[derive(Debug, Clone)]
enum Step {
    Run(Budget),
    Toggle(usize),
    Push(usize, u64),
}

fn step(max_charge: u64) -> impl Strategy<Value = Step> {
    prop_oneof![
        (0u32..12, 0u64..4_000).prop_map(|(work, bytes)| Step::Run(Budget { work, bytes })),
        (0usize..MAX_LANES).prop_map(Step::Toggle),
        (0usize..MAX_LANES, 1..=max_charge).prop_map(|(lane, charge)| Step::Push(lane, charge)),
    ]
}

proptest! {
    /// Under any interleaving of calls, budgets, arrivals and eligibility
    /// changes: credits equal service, forfeits and the deficit held; a
    /// lane between visits holds less than the maximum charge; no call
    /// serves more bytes than its budget; and a zero-work call changes
    /// nothing.
    #[test]
    fn credits_are_conserved_and_residuals_bounded(
        quanta in prop::collection::vec(1_500u64..5_000, 1..=MAX_LANES),
        steps in prop::collection::vec(step(1_500), 1..300),
    ) {
        let mut drr = drr(&quanta, 1_500);
        let lanes = quanta.len();
        let mut model = Model::default();
        let mut totals = Totals::default();
        for step in steps {
            match step {
                Step::Toggle(lane) => model.closed[lane] = !model.closed[lane],
                Step::Push(lane, charge) => model.queues[lane].push_back(charge),
                Step::Run(budget) => {
                    let before = (drr.cursor(), drr.in_visit(), drr.deficit);
                    let report = drr.run(budget, &mut model);
                    let served: u64 = report.lanes.iter().map(|lane| lane.served_bytes).sum();
                    prop_assert!(served <= budget.bytes);
                    if budget.work == 0 {
                        prop_assert_eq!(before, (drr.cursor(), drr.in_visit(), drr.deficit));
                    }
                    totals.add(&report);
                }
            }
            prop_assert!(conserved(&drr, &totals));
            for lane in 0..lanes {
                if lane != drr.cursor() || !drr.in_visit() {
                    prop_assert!(drr.deficit(lane).unwrap() < 1_500);
                }
            }
        }
    }
}
