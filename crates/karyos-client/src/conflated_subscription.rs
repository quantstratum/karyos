// SPDX-License-Identifier: Apache-2.0

//! Client view of a keyed conflation table (SPEC.md §7.1, §10).

use karyos_sys::conflation::{Budget, ConflationReader, PollReport};

/// A bounded reader of the latest coherent value for each changed key.
///
/// The reader's private buffers are allocated when it is created. A handler
/// receives a borrowed copy that does not hold a slot or publication loan.
#[must_use]
pub struct ConflatedSubscription {
    reader: ConflationReader,
    budget: Budget,
}

impl ConflatedSubscription {
    /// Wraps a reader and the budget used by [`Self::poll_changed`].
    pub fn new(reader: ConflationReader, budget: Budget) -> Self {
        Self { reader, budget }
    }

    /// Delivers changed keys using this subscription's budget.
    ///
    /// Intermediate versions may be skipped. A handler panic leaves its key
    /// pending for a later poll.
    pub fn poll_changed(&mut self, mut handler: impl FnMut(u32, &[u8])) -> PollReport {
        self.reader
            .poll_changed(self.budget, |key, _version, value| handler(key, value))
    }

    /// Delivers changed keys with versions using an explicit budget.
    ///
    /// Intermediate versions may be skipped. A handler panic leaves its key
    /// pending for a later poll.
    pub fn poll_changed_with(
        &mut self,
        budget: Budget,
        handler: impl FnMut(u32, u64, &[u8]),
    ) -> PollReport {
        self.reader.poll_changed(budget, handler)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karyos_sys::conflation::conflation;

    #[test]
    fn poll_changed_uses_the_subscription_budget_and_hides_versions() {
        let mut writer = conflation(2, 8, 1024).unwrap();
        let mut subscription = ConflatedSubscription::new(
            writer.reader(),
            Budget {
                keys: 2,
                retries: 2,
            },
        );
        writer.write(1, b"value").unwrap();
        let mut seen = Vec::new();

        let report = subscription.poll_changed(|key, value| {
            seen.push((key, value.to_vec()));
        });

        assert_eq!(report.delivered, 1);
        assert_eq!(seen, vec![(1, b"value".to_vec())]);
    }

    #[test]
    fn poll_changed_with_uses_its_budget_and_reports_versions() {
        let mut writer = conflation(3, 8, 1024).unwrap();
        let mut subscription = ConflatedSubscription::new(
            writer.reader(),
            Budget {
                keys: 0,
                retries: 0,
            },
        );
        let version = writer.write(2, b"new").unwrap();
        let mut seen = Vec::new();

        let report = subscription.poll_changed_with(
            Budget {
                keys: 3,
                retries: 1,
            },
            |key, found_version, value| {
                seen.push((key, found_version, value.to_vec()));
            },
        );

        assert_eq!(report.delivered, 1);
        assert_eq!(seen, vec![(2, version, b"new".to_vec())]);
    }
}
