#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! Network text is cleaned in one place. A new `is_control` outside `text.rs` is a second,
//! weaker idea of an unsafe character: use `zombo_core::text` instead.

use std::path::{Path, PathBuf};

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn no_source_outside_text_rs_calls_is_control() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = vec![];
    sources(&src, &mut files);
    let offenders: Vec<_> = files
        .iter()
        .filter(|p| !p.ends_with("text.rs"))
        .filter(|p| std::fs::read_to_string(p).unwrap().contains("is_control"))
        .collect();
    assert!(
        offenders.is_empty(),
        "{offenders:?} use is_control; clean network text with zombo_core::text (printable, strip, single_line, is_unsafe_char)"
    );
}
