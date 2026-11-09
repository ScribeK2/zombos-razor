#![no_main]

use libfuzzer_sys::fuzz_target;
use zombo_core::evidence::maillog::{analyse_maillog, decode_reason, maillog_findings};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Ok(a) = analyse_maillog(&text) {
        zombo_fuzz::check_findings(&maillog_findings(&a));
    }
    if let Some((dsn, reply)) = text.split_once('\n') {
        let _ = decode_reason(dsn, reply);
    }
});
