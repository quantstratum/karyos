// SPDX-License-Identifier: Apache-2.0

//! Loom models of ending a registration (`quantstratum-docs:
//! karyos/design/ipc-data-path.md`, Ending a registration), composed from
//! the production helpers of `karyos_sys::registration`: an end racing a
//! stale adoption of the same export, and a delayed end racing the
//! adoption of the cell's next occupant.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::registration::{ADOPTED, claim, end};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::sync::Arc;
use loom::thread;

const OLD: u64 = 5;
const NEW: u64 = 9;

/// The driver ends export 5 and reuses the cell for export 9 while a stale
/// participant tries to adopt export 5. The stale adoption either comes
/// first (and the end still clears it) or fails; it never spends the new
/// grant, whose adoption always succeeds.
#[test]
fn an_end_racing_a_stale_adoption_never_spends_the_next_grant() {
    loom::model(|| {
        let word = Arc::new(AtomicU64::new(OLD));
        let driver = {
            let word = Arc::clone(&word);
            thread::spawn(move || {
                let ended = end(&word, OLD);
                word.store(NEW, Ordering::Release);
                ended
            })
        };
        let stale = claim(&word, OLD);
        assert!(driver.join().unwrap(), "the end missed its export");
        // Whatever the stale adoption did, the word names only the new
        // grant, unadopted.
        assert_eq!(word.load(Ordering::Acquire), NEW);
        assert!(claim(&word, NEW));
        assert!(!claim(&word, OLD));
        let _ = stale;
    });
}

/// A delayed end of export 5 races the adoption of export 9, which now
/// occupies the cell: the end touches nothing and the adoption succeeds.
#[test]
fn a_delayed_end_never_touches_the_next_occupant() {
    loom::model(|| {
        let word = Arc::new(AtomicU64::new(NEW));
        let driver = {
            let word = Arc::clone(&word);
            thread::spawn(move || end(&word, OLD))
        };
        assert!(claim(&word, NEW));
        assert!(!driver.join().unwrap());
        assert_eq!(word.load(Ordering::Acquire), NEW | ADOPTED);
    });
}

/// An end racing the adoption of the same export always clears the word:
/// either it clears the bare export (and the adoption fails) or it clears
/// the adopted one.
#[test]
fn an_end_racing_an_adoption_always_ends() {
    loom::model(|| {
        let word = Arc::new(AtomicU64::new(OLD));
        let driver = {
            let word = Arc::clone(&word);
            thread::spawn(move || end(&word, OLD))
        };
        let adopted = claim(&word, OLD);
        assert!(driver.join().unwrap());
        assert_eq!(word.load(Ordering::Acquire), 0);
        // A later adoption fails whichever came first.
        assert!(!claim(&word, OLD));
        let _ = adopted;
    });
}
