### Changed

- The Archive's signing poll keeps in memory only the integrity journal records no signed head covers yet (from the oldest pending head, or the last record when nothing is pending) plus the key registry records, instead of every record read since start; `HeadSigning::poll_from` polls against such a tail and `HeadSigning::oldest_pending` names where it starts (karyos#1095).
