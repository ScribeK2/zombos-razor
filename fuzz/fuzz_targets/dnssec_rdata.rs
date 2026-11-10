#![no_main]

use std::time::SystemTime;

use libfuzzer_sys::fuzz_target;
use zombo_core::dnssec::{Algorithm, Dnskey, Ds, Rrsig};

fuzz_target!(|data: &[u8]| {
    if let Some(sig) = Rrsig::from_rdata(data) {
        let _ = sig.window(SystemTime::now());
        let _ = sig.window(SystemTime::UNIX_EPOCH);
        let _ = sig.type_covered();
    }
    let _ = Ds::from_rdata(data);
    if let Some(key) = Dnskey::from_rdata(data) {
        let _ = key.is_ksk();
    }
    let _ = Algorithm::from_number(data.first().copied().unwrap_or(0)).deprecated();
});
