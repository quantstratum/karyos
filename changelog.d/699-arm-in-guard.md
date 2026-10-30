### Fixed

- The test kit's `karyos_test_panic_next_duty_cycle` arms its fault
  inside the driver table's guard (karyos#699). A close racing the arm
  either comes after it and disarms it, or makes the arm fail with the
  handle's error; the fault is never left armed on a closed driver.
