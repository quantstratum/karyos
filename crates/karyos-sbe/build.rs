// SPDX-License-Identifier: Apache-2.0

//! Generates the SBE 1.0 codecs of `schemas/` with IronSBE's generator
//! (karyos#646): Real Logic's example schema, `Car` version 0, and its
//! extension, version 1. The schemas include `common-types.xml` with
//! `xi:include`, which the generator does not resolve, so it is expanded in
//! place first. Setters that could panic are not generated: every variable
//! field is set through a `try_set_*` that returns an error instead.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

/// The schemas and the file each one's codecs are written to.
const SCHEMAS: [(&str, &str); 2] = [
    ("example-schema.xml", "car_v0.rs"),
    ("example-extension-schema.xml", "car_v1.rs"),
];

/// `file` with its `xi:include` of `common-types.xml` expanded in place.
fn expanded(dir: &Path, file: &str) -> Result<String, Box<dyn Error>> {
    let schema = fs::read_to_string(dir.join(file))?;
    let common = fs::read_to_string(dir.join("common-types.xml"))?;
    let common = common
        .split_once("?>")
        .map_or(common.as_str(), |(_, body)| body)
        .trim();
    let include = r#"<xi:include href="common-types.xml"/>"#;
    if !schema.contains(include) {
        return Err(format!("{file}: no include of common-types.xml").into());
    }
    Ok(schema.replace(include, common))
}

fn main() -> Result<(), Box<dyn Error>> {
    let dir = PathBuf::from("schemas");
    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=schemas");
    for (file, generated) in SCHEMAS {
        let options = ironsbe_codegen::GeneratorOptions::default().with_panicking_setters(false);
        let code =
            ironsbe_codegen::generate_from_xml_with_options(&expanded(&dir, file)?, options)?;
        fs::write(out.join(generated), code)?;
    }
    Ok(())
}
