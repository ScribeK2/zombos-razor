#![no_main]

use libfuzzer_sys::fuzz_target;
use zombo_core::evidence::headers::{analyse_headers, header_findings};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Ok(a) = analyse_headers(&text) {
        zombo_fuzz::check_findings(&header_findings(&a));
    }
});
