//! Fixtures for the Evidence tests: the shared files in `testdata/evidence`.
#![allow(dead_code)]

use std::path::PathBuf;

pub fn fixture(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../testdata/evidence/{name}"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}
