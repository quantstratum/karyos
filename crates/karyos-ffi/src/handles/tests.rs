// SPDX-License-Identifier: Apache-2.0

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Barrier};

use super::*;

#[test]
fn a_handle_names_its_object_until_it_is_closed() {
    let table = Table::new(Kind::Client, 4);
    let handle = table.insert(7_u32).unwrap();
    assert_ne!(handle.raw(), 0);
    assert_eq!(table.with(handle, |value| *value), Ok(7));
    table.with(handle, |value| *value = 8).unwrap();
    assert_eq!(table.remove(handle), Ok(8));
    assert_eq!(table.with(handle, |value| *value), Err(Status::Closed));
    // A second close finds the stale generation.
    assert_eq!(table.remove(handle), Err(Status::Closed));
}

#[test]
fn a_reused_slot_does_not_answer_its_old_handle() {
    let table = Table::new(Kind::Client, 1);
    let first = table.insert(1_u32).unwrap();
    table.remove(first).unwrap();
    let second = table.insert(2_u32).unwrap();
    assert_eq!(first.index(), second.index());
    assert_ne!(first, second);
    assert_eq!(table.with(first, |value| *value), Err(Status::Closed));
    assert_eq!(table.with(second, |value| *value), Ok(2));
}

#[test]
fn zero_another_kind_and_an_index_out_of_range_are_not_handles() {
    let table = Table::new(Kind::Client, 2);
    let handle = table.insert(1_u32).unwrap();
    assert_eq!(
        table.with(Handle::from_raw(0), |value| *value),
        Err(Status::InvalidHandle)
    );
    let other = Table::new(Kind::Publication, 2);
    assert_eq!(
        other.with(handle, |value: &mut u32| *value),
        Err(Status::InvalidHandle)
    );
    let beyond = Handle::new(Kind::Client, 2, handle.generation());
    assert_eq!(
        table.with(beyond, |value| *value),
        Err(Status::InvalidHandle)
    );
    // A handle whose generation is 0 names nothing, even in range.
    let unset = Handle::new(Kind::Client, handle.index(), 0);
    assert_eq!(
        table.with(unset, |value| *value),
        Err(Status::InvalidHandle)
    );
}

#[test]
fn a_full_table_refuses_another_handle() {
    let table = Table::new(Kind::Client, 2);
    let first = table.insert(1_u32).unwrap();
    table.insert(2_u32).unwrap();
    assert_eq!(table.insert(3_u32), Err(Status::HandlesExhausted));
    table.remove(first).unwrap();
    assert!(table.insert(3_u32).is_ok());
}

#[test]
fn a_slot_whose_generation_cannot_grow_is_retired() {
    let table = Table::new(Kind::Client, 1);
    table.set_generation(0, u32::MAX - 1);
    let last = table.insert(1_u32).unwrap();
    assert_eq!(last.generation(), u32::MAX);
    table.remove(last).unwrap();
    // Never reused, so no handle can come back at a wrapped generation.
    assert_eq!(table.insert(2_u32), Err(Status::HandlesExhausted));
    assert_eq!(table.with(last, |value| *value), Err(Status::Closed));
}

#[test]
fn a_callback_that_reenters_its_handle_is_refused() {
    let table = Table::new(Kind::Subscription, 2);
    let handle = table.insert(1_u32).unwrap();
    let other = table.insert(2_u32).unwrap();
    let inner = table
        .with(handle, |_| {
            (
                table.with(handle, |value| *value),
                table.remove(handle),
                table.with(other, |value| *value),
            )
        })
        .unwrap();
    assert_eq!(inner.0, Err(Status::Reentrant));
    // Closing the handle from its own callback is refused as a whole.
    assert_eq!(inner.1, Err(Status::Reentrant));
    // Another handle is free to use.
    assert_eq!(inner.2, Ok(2));
    assert_eq!(table.with(handle, |value| *value), Ok(1));
}

#[test]
fn another_thread_finds_a_held_handle_busy() {
    let table = Arc::new(Table::new(Kind::Publication, 1));
    let handle = table.insert(1_u32).unwrap();
    let held = Arc::new(Barrier::new(2));
    let tried = Arc::new(Barrier::new(2));
    let other = {
        let (table, held, tried) = (Arc::clone(&table), Arc::clone(&held), Arc::clone(&tried));
        std::thread::spawn(move || {
            held.wait();
            let seen = (table.with(handle, |value| *value), table.remove(handle));
            tried.wait();
            seen
        })
    };
    table
        .with(handle, |_| {
            held.wait();
            tried.wait();
        })
        .unwrap();
    let (used, closed) = other.join().unwrap();
    assert_eq!(used, Err(Status::Busy));
    assert_eq!(closed, Err(Status::Busy));
    assert_eq!(table.with(handle, |value| *value), Ok(1));
}

#[test]
fn a_panic_poisons_the_handle_until_it_is_closed() {
    let table = Table::new(Kind::Client, 1);
    let handle = table.insert(1_u32).unwrap();
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        table
            .with(handle, |_| std::panic::resume_unwind(Box::new("in a call")))
            .unwrap();
    }));
    assert!(unwound.is_err());
    assert_eq!(table.with(handle, |value| *value), Err(Status::Internal));
    // The holder was cleared by the unwinding: not reentrant, poisoned.
    assert_eq!(table.with(handle, |value| *value), Err(Status::Internal));
    assert_eq!(table.remove(handle), Ok(1));
    let next = table.insert(2_u32).unwrap();
    assert_eq!(table.with(next, |value| *value), Ok(2));
}

#[test]
fn a_capacity_above_the_index_range_is_clamped() {
    let table: Table<u32> = Table::new(Kind::Client, 0);
    assert_eq!(table.insert(1), Err(Status::HandlesExhausted));
    assert_eq!(MAX_CAPACITY, 1 << INDEX_BITS);
}

#[test]
fn a_stale_close_leaves_the_poison_of_the_live_handle() {
    let table = Table::new(Kind::Client, 1);
    let stale = table.insert(1_u32).unwrap();
    table.remove(stale).unwrap();
    let live = table.insert(2_u32).unwrap();
    assert_eq!(stale.index(), live.index());
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        table
            .with(live, |_| std::panic::resume_unwind(Box::new("in a call")))
            .unwrap();
    }));
    assert!(unwound.is_err());
    assert_eq!(table.with(live, |value| *value), Err(Status::Internal));
    // The stale handle is closed, poisoned slot or not.
    assert_eq!(table.with(stale, |value| *value), Err(Status::Closed));
    assert_eq!(table.remove(stale), Err(Status::Closed));
    assert_eq!(table.with(live, |value| *value), Err(Status::Internal));
    assert_eq!(table.remove(live), Ok(2));
}

#[test]
fn a_create_waits_out_a_stale_use_of_its_free_slot() {
    let table = Arc::new(Table::new(Kind::Client, 1));
    let stale = table.insert(1_u32).unwrap();
    table.remove(stale).unwrap();
    let inserted = {
        // Held as a use of the stale handle holds it to compare
        // generations.
        let _comparing = table.slots[0].entry.lock().unwrap();
        let table = Arc::clone(&table);
        let inserting = std::thread::spawn(move || table.insert(2_u32));
        std::thread::sleep(std::time::Duration::from_millis(10));
        inserting
    };
    let live = inserted.join().unwrap().unwrap();
    assert_eq!(table.with(live, |value| *value), Ok(2));
    table.remove(live).unwrap();
    // The slot went back to the free list: capacity is intact.
    assert!(table.insert(3_u32).is_ok());
}
