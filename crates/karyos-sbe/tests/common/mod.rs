// SPDX-License-Identifier: Apache-2.0

//! The golden vectors' values (`vectors/Vectors.java`) and their encoding
//! with the generated codecs, shared by the tests.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

/// The bytes of a golden vector file: its `#` lines (the SPDX line) skipped,
/// then one line of lowercase hex.
pub fn vector(file: &str) -> Vec<u8> {
    let hex: String = file
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect::<String>();
    let hex = hex.trim();
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

/// `someNumbers`: the uint32 array 1, 2, 3, 4, as its bytes.
pub fn some_numbers() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for (at, n) in [1u32, 2, 3, 4].iter().enumerate() {
        bytes[at * 4..at * 4 + 4].copy_from_slice(&n.to_le_bytes());
    }
    bytes
}

/// `uuid` of version 1: the int64 array 7, 3, as its bytes.
pub fn uuid() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&7i64.to_le_bytes());
    bytes[8..].copy_from_slice(&3i64.to_le_bytes());
    bytes
}

/// The fuel figures: speed, mpg and usage description.
pub const FUEL: [(u16, f32, &[u8]); 3] = [
    (30, 35.9, b"Urban Cycle"),
    (55, 49.0, b"Combined Cycle"),
    (75, 40.0, b"Highway Cycle"),
];

/// The performance figures: octane rating and (mph, seconds) accelerations.
pub const PERFORMANCE: [(u8, [(u16, f32); 3]); 2] = [
    (95, [(30, 4.0), (60, 7.5), (100, 12.2)]),
    (99, [(30, 3.8), (60, 7.1), (100, 11.8)]),
];

/// Encodes the vectors' `Car` with one schema version's codecs into `buf`;
/// returns its length. `$extend` sets what only that version has.
#[macro_export]
macro_rules! encode_car {
    ($module:path, $buf:expr, $extend:expr) => {{
        use $module as m;
        let mut car = m::CarEncoder::wrap($buf, 0).unwrap();
        car.set_serial_number(1234)
            .set_model_year(2013)
            .set_available(m::BooleanType::T)
            .set_code(m::Model::A)
            .set_some_numbers(&common::some_numbers())
            .set_vehicle_code(b"abcdef");
        let mut extras = m::OptionalExtras::new();
        extras.set_sports_pack();
        extras.set_cruise_control();
        car.set_extras(extras);
        {
            let mut engine = car.set_engine();
            engine
                .set_capacity(2000)
                .set_num_cylinders(4)
                .set_manufacturer_code(b"123")
                .set_efficiency(35)
                .set_booster_enabled(m::BooleanType::T);
            engine
                .booster()
                .set_boost_type(m::BoostType::NITROUS)
                .set_horse_power(200);
        }
        $extend(&mut car);
        {
            let mut fuel = car.fuel_figures_count(3).unwrap();
            for (speed, mpg, usage) in common::FUEL {
                let mut entry = fuel.next_entry().unwrap().unwrap();
                entry.set_speed(speed).set_mpg(mpg);
                entry.try_set_usage_description(usage).unwrap();
            }
        }
        {
            let mut perf = car.performance_figures_count(2).unwrap();
            for (octane, accelerations) in common::PERFORMANCE {
                let mut entry = perf.next_entry().unwrap().unwrap();
                entry.set_octane_rating(octane);
                let mut acceleration = entry.acceleration_count(3).unwrap();
                for (mph, seconds) in accelerations {
                    acceleration
                        .next_entry()
                        .unwrap()
                        .unwrap()
                        .set_mph(mph)
                        .set_seconds(seconds);
                }
            }
        }
        car.try_set_manufacturer(b"Honda").unwrap();
        car.try_set_model(b"Civic VTi").unwrap();
        car.try_set_activation_code(b"abcdef").unwrap();
        car.encoded_length()
    }};
}
