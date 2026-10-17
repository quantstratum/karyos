// SPDX-License-Identifier: Apache-2.0

//! Loom model of a required subscriber joining an image while its receive
//! owner samples the required cells for an SM (phase 5d, ACS 15808), over
//! the production helpers of `karyos_sys::participant`.
//!
//! The owner publishes its head (the rebuild position, Release), then
//! samples the cells (`required_minimum`) and reports the least of its head
//! and the sample. The conductor reads the head, admits a required cell at
//! it (`admit`, the state published last), then rechecks the head
//! (`join_after_admit`) and moves the join forward if it rose. Whatever
//! the interleaving, the reported consumption never exceeds the join.
//!
//! The negative control drops both fences (plain Acquire loads): the owner
//! can miss the admission while the conductor misses the new head, the
//! store buffering the fences rule out, and the report passes the join.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::participant::{
    CELL_FREE, CELL_REQUIRED, admit, join_after_admit, reader_minima, required_minimum,
};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::sync::Arc;
use loom::thread;

struct Image {
    head: AtomicU64,
    state: AtomicU64,
    revoked: AtomicU64,
    registration: AtomicU64,
    position: AtomicU64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Order {
    Production,
    NoFences,
}

fn model(order: Order) {
    loom::model(move || {
        let image = Arc::new(Image {
            head: AtomicU64::new(0),
            state: AtomicU64::new(CELL_FREE),
            revoked: AtomicU64::new(0),
            registration: AtomicU64::new(0),
            position: AtomicU64::new(0),
        });
        let conductor = {
            let image = Arc::clone(&image);
            thread::spawn(move || {
                let start = image.head.load(Ordering::Acquire);
                image.position.store(start, Ordering::Relaxed);
                admit(
                    &image.state,
                    &image.revoked,
                    &image.registration,
                    1,
                    CELL_REQUIRED,
                );
                let join = match order {
                    Order::Production => join_after_admit(&image.head, start),
                    Order::NoFences => image.head.load(Ordering::Acquire).max(start),
                };
                if join > start {
                    image.position.store(join, Ordering::Release);
                }
                join
            })
        };
        // The owner commits up to 64 and publishes it, then samples.
        let rebuild = 64;
        image.head.store(rebuild, Ordering::Release);
        let cells = [(&image.state, &image.position)];
        let sampled = match order {
            Order::Production => required_minimum(cells),
            Order::NoFences => reader_minima(cells).0,
        };
        let consumption = sampled.map_or(rebuild, |required| required.min(rebuild));
        let join = conductor.join().unwrap();
        assert!(
            consumption <= join,
            "consumption {consumption} past the join {join}"
        );
    });
}

#[test]
fn a_sample_never_reports_past_a_racing_join() {
    model(Order::Production);
}

#[test]
#[should_panic(expected = "past the join")]
fn control_without_fences_reports_past_the_join() {
    model(Order::NoFences);
}
