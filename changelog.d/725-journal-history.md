### Added

- The operations journal's history and change stream (R-CORE-14, karyos#725), new in agent API v1 with every existing answer unchanged:
  - **`journal-history [RECORDING POSITION [COUNT]]`:** a page of the journal's durable records from a cursor, or from the retention floor without one, at most 256 records (64 by default). Each record carries its `position` and the `next` record's, so a reader detects a gap from the sequence alone; the page states the journal's `recording`, retention `floor`, durable `head` and `next`. A cursor is the recording and a position, and survives the agent's restarts, clean or not.
  - **Refusals, typed:** a cursor below the floor (`below_floor`, with the floor), of another recording (`recording_changed`), past the durable end (`ahead`) or not at a record (`not_a_record`) is refused, never answered with an empty page.
  - **Explicit gaps:** an unknown interval the journal recorded is served in place as `unknown_interval` with its `gap_reason`, and listed in the page's `unknown_intervals`.
  - **The handoff:** the view's `journal.head` is the journal's recording and durable end when the view was taken; a reader that follows the history from it misses no record written after the view and sees none written before it again.
  - **Bounds:** the new `limits` dimension `journal.history_records` (256, fixed); the capability `journal-history`, served to every role while the journal can be read. The micro bench `journal history` measures a full page.
