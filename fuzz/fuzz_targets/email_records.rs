#![no_main]

use libfuzzer_sys::fuzz_target;
use zombo_core::email_auth::{
    parse_bimi, parse_dkim_key, parse_dmarc, parse_mta_sts, parse_selectors, parse_spf, parse_tls_rpt, spf_records,
};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let lines: Vec<String> = text.lines().take(64).map(str::to_string).collect();
    let _ = spf_records(&lines);
    let _ = parse_tls_rpt(&lines);
    let _ = parse_bimi(&lines);
    let _ = parse_mta_sts(&lines);
    let _ = parse_selectors(&lines);
    for l in &lines {
        let _ = parse_spf("example.com", l);
        let _ = parse_dmarc(l);
        let _ = parse_dkim_key("sel", None, l);
        let _ = parse_dkim_key("sel", Some("sel.provider.example"), l);
    }
    let _ = parse_spf("example.com", &text);
    let _ = parse_dmarc(&text);
    let _ = parse_dkim_key("sel", None, &text);
});
