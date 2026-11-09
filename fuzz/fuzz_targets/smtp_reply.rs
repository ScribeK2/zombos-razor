#![no_main]

use libfuzzer_sys::fuzz_target;
use zombo_core::smtp::{Extensions, banner_host};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let lines: Vec<String> = text.lines().take(64).map(str::to_string).collect();
    let _ = Extensions::parse(&lines);
    let _ = banner_host(&text);
    zombo_fuzz::block_on(zombo_core::untrusted::smtp_replies(data.to_vec()));
});
