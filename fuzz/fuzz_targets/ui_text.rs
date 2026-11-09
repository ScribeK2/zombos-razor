#![no_main]

use libfuzzer_sys::fuzz_target;
use zombo_ui::{
    evidence_model::{display_text, sniff},
    settings_model,
};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = sniff(&text);
    let shown = display_text(&text);
    assert!(!shown.chars().any(|c| c.is_control() && c != '\n'), "control character survived display_text");
    let _ = settings_model::parse(&text);
});
