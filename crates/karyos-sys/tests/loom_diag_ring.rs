// SPDX-License-Identifier: Apache-2.0

//! Loom model of the diagnostic record ring of `karyos_sys::diag_ring`
//! (`quantstratum-docs: karyos/design/observability-and-tools.md`, "Error
//! log"), over the production writer and reader.
//!
//! A ring of one record: the writer appends record 0, updates it in place,
//! then appends record 1 over it. A concurrent reader scans from sequence
//! 0. Every record it delivers must be whole (its two fields belong to one
//! write), carry the sequence it was read as, and only the boundary may
//! report an overwrite. Negative control: a writer that skips the seqlock
//! lets the reader deliver a torn record.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::diag_ring::{
    FIELDS, RingReader, RingWriter, STRIDE_WORDS, ScanStop, ring_words, scan,
};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::sync::Arc;
use loom::thread;

/// Words per record: version, sequence and two fields.
const RECORD: usize = FIELDS + 2;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Writer {
    Seqlock,
    Plain,
}

/// The fields of the `k`-th write: two words that must be seen together.
fn fields(k: u64) -> [u64; 2] {
    [10 * k, 10 * k + 1]
}

fn model(writer_kind: Writer) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(move || {
        let words: Arc<Vec<AtomicU64>> = Arc::new(
            (0..ring_words(1, RECORD).unwrap())
                .map(|_| AtomicU64::new(0))
                .collect(),
        );
        // Record 0, published before the reader starts.
        let _ = RingWriter::create(&words, 1, RECORD)
            .unwrap()
            .append(&fields(1))
            .unwrap();
        let writer = {
            let words = Arc::clone(&words);
            thread::spawn(move || match writer_kind {
                Writer::Seqlock => {
                    let mut ring = RingWriter::resume(&words, RECORD).unwrap();
                    assert!(ring.update(0, &fields(2)));
                    let _ = ring.append(&fields(3)).unwrap();
                }
                Writer::Plain => {
                    // Rewrite record 0's fields without the seqlock.
                    let [a, b] = fields(2);
                    words[STRIDE_WORDS + FIELDS].store(a, Ordering::Relaxed);
                    words[STRIDE_WORDS + FIELDS + 1].store(b, Ordering::Relaxed);
                }
            })
        };
        let reader = RingReader::new(
            |index| words.get(index).map(|word| word.load(Ordering::Relaxed)),
            RECORD,
        )
        .unwrap();
        let mut cursor = 0;
        let mut buffer = [0u64; 2];
        let result = scan(&reader, &mut cursor, &mut buffer, |seq, read| {
            assert_eq!(read[1], read[0] + 1, "a delivered record is torn");
            // Record 0 holds write 1 or its update (write 2); record 1
            // holds write 3.
            let expected: &[u64] = if seq == 0 { &[10, 20] } else { &[30] };
            assert!(expected.contains(&read[0]), "record {seq} holds {read:?}");
        });
        if result.overwritten > 0 {
            // Only the boundary proves an overwrite: record 1 is published.
            assert_eq!(cursor, 2);
        }
        if result.stopped == Some(ScanStop::Overwritten) {
            assert_eq!(cursor, 0);
        }
        writer.join().unwrap();
    });
}

#[test]
fn delivered_records_are_whole() {
    model(Writer::Seqlock);
}

#[test]
#[should_panic(expected = "a delivered record is torn")]
fn control_a_plain_write_can_be_torn() {
    model(Writer::Plain);
}
