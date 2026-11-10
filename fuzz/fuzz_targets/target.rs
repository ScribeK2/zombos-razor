#![no_main]

use libfuzzer_sys::fuzz_target;
use zombo_core::{
    rdns::reverse_name,
    registration::registrable_domain,
    resolver::{parse_addr, parse_resolv_conf},
    smtp::valid_ehlo_name,
    target::parse_target,
    web::parse_web_target,
};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = parse_target(&text);
    let _ = parse_web_target(&text);
    let _ = registrable_domain(&text);
    let _ = valid_ehlo_name(&text);
    let _ = parse_addr(&text);
    let _ = parse_resolv_conf(&text);
    let _ = zombo_core::untrusted::banner(data);
    if let Ok(ip) = text.trim().parse() {
        let _ = reverse_name(ip);
    }
});
