#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! One test per defect found by fuzzing or hostile input, each with the input that found it.

use zombo_core::{dnssec::Dnskey, untrusted};

#[test]
fn a_dnskey_longer_than_any_real_key_has_a_key_tag_without_overflowing() {
    // 4 MiB of 0xff summed in 32 bits: this panicked in debug builds with "attempt to add with overflow".
    let mut rdata = vec![1, 1, 3, 13];
    rdata.extend(vec![0xff; 4 << 20]);
    assert!(Dnskey::from_rdata(&rdata).is_some());
}

#[test]
fn whois_text_cannot_put_control_characters_in_a_finding() {
    let text =
        "Registrar: a\u{1b}[31m\0b\nName Server: ns\u{7}1.example\nStatus: ACT\u{0}IVE\nExpiry Date: 1\u{1b}[2J\n";
    let findings = untrusted::whois(text);
    assert!(!findings.is_empty());
    for f in &findings {
        assert!(!f.message.chars().any(|c| c.is_control() && c != '\n'), "{:?}", f.message);
        assert!(!f.title.chars().any(|c| c.is_control()), "{:?}", f.title);
    }
}

#[test]
fn rdap_text_cannot_put_control_characters_in_a_finding() {
    let body =
        br#"{"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["fn",{},"text","Evil\u0000\u001b[2J Inc"]]]}],
        "status":["a\u0000b"],"nameservers":[{"ldhName":"n\u0007s.example"}],
        "events":[{"eventAction":"expiration","eventDate":"x\u001b[2Jy"}]}"#;
    let findings = untrusted::rdap(body);
    assert!(!findings.is_empty());
    for f in &findings {
        assert!(!f.message.chars().any(|c| c.is_control() && c != '\n'), "{:?}", f.message);
    }
}
