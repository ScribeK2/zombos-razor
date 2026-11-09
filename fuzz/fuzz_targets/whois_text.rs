#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    zombo_fuzz::check_findings(&zombo_core::untrusted::whois(&String::from_utf8_lossy(data)));
});
