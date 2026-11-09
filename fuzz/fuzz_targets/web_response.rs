#![no_main]

use libfuzzer_sys::fuzz_target;
use zombo_core::web::web_findings;

fuzz_target!(|data: &[u8]| {
    let (head, body) = match data.iter().position(|&b| b == 0) {
        Some(i) => (data.get(..i).unwrap_or_default(), data.get(i + 1..).unwrap_or_default()),
        None => (data, &[][..]),
    };
    let r = zombo_core::untrusted::web_page(&String::from_utf8_lossy(head), body);
    zombo_fuzz::check_findings(&web_findings("example.com", &r));
});
