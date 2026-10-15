// The conductor's diagnostic accessors (`quantstratum-docs:
// karyos/design/observability-and-tools.md`, phase 1 driver counters).

#[test]
fn diagnostics_count_credits_loans_and_quarantine() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    assert_eq!(conductor.quarantined_slots(), 0);
    // The exclusive publication's credit is reserved for the buffer's life.
    assert_eq!(conductor.spare_credits(), 1);
    let loans = conductor.loans_outstanding();
    // An optional reader holds a spare-slot credit; a required one under
    // the default policy does not.
    let _optional = conductor.subscribe(Role::Optional).unwrap();
    assert_eq!(conductor.spare_credits(), 2);
    let _required = conductor.subscribe(Role::Required).unwrap();
    assert_eq!(conductor.spare_credits(), 2);
    // The publication takes its first term write loan when it is issued.
    let _publication = buffer.publication().unwrap().unwrap();
    assert!(conductor.loans_outstanding() > loans);
    assert_eq!(conductor.quarantined_slots(), 0);
}
