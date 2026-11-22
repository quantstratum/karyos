### Changed

- Tests: more load-sensitive tests from karyos#1067. The two-path driver tests wait, bounded, for the second path to bind before their first message; the retention-floor tests wait for each receiver's path to bind and report every counter if B never reads; the tool attach rollback test checks that no descriptor is left open instead of comparing counts, which a previous test's late close could lower; and the C ABI retired-image test accepts the documented 0 of a seal not positioned yet when the image retired.
