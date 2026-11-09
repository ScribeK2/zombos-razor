#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! Text from the network that holds a right-to-left override (U+202E) and a zero width space
//! (U+200B) must not survive into a Finding, for every source of text.

#[path = "common/tls.rs"]
mod pki;

use std::time::Duration;

use pki::{Ca, NOW};
use zombo_core::{
    Finding,
    evidence::{
        headers::{analyse_headers, header_findings},
        maillog::{analyse_maillog, maillog_findings},
    },
    tls::{check_tls_via, tls_findings_at},
    untrusted,
    update::notes_preview,
    web::web_findings,
};

const OVERRIDE: char = '\u{202e}';
const ZERO_WIDTH: char = '\u{200b}';

fn all_text(fs: &[Finding]) -> String {
    fs.iter()
        .map(|f| format!("{} {} {}", f.title, f.message, f.recommendation.as_deref().unwrap_or_default()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The text is non-empty and reached the output (so the test is not vacuous), minus the two characters.
fn clean(text: &str, marker: &str) {
    assert!(text.contains(marker), "{marker:?} never reached the output: {text:?}");
    assert!(!text.contains(OVERRIDE) && !text.contains(ZERO_WIDTH), "{text:?}");
}

#[test]
fn whois_registrar_text() {
    let fs = untrusted::whois(
        "Domain Name: EXAMPLE.COM\nRegistrar: Evil\u{202e}Corp\u{200b}Ltd\nRegistry Expiry Date: 2099-01-01T00:00:00Z\n",
    );
    clean(&all_text(&fs), "Evil\u{fffd}Corp\u{fffd}Ltd");
}

#[test]
fn rdap_registrar_text() {
    let body = "{\"entities\":[{\"roles\":[\"registrar\"],\"vcardArray\":[\"vcard\",[[\"fn\",{},\"text\",\"Evil\\u202eCorp\\u200bLtd\"]]]}],\"events\":[{\"eventAction\":\"expiration\",\"eventDate\":\"2099-01-01T00:00:00Z\"}]}"
        .as_bytes();
    let fs = untrusted::rdap(body);
    clean(&all_text(&fs), "Evil\u{fffd}Corp\u{fffd}Ltd");
}

#[test]
fn smtp_or_port_banner() {
    let banner = untrusted::banner("220 mail\u{202e}.example\u{200b} ESMTP\r\n".as_bytes()).unwrap();
    assert_eq!(banner, "220 mail.example ESMTP");
}

#[tokio::test]
async fn certificate_names() {
    let root = Ca::root("Test Root CA");
    let inter = root.intermediate("Evil\u{202e}CA\u{200b}Ltd");
    let leaf = inter.valid_leaf(&["example.test"]);
    let addr = pki::serve(vec![leaf.der, inter.der()], leaf.key).await;
    let r = check_tls_via(addr, "example.test", &root.roots(), NOW, Duration::from_secs(5)).await.unwrap();
    for c in &r.chain {
        for s in [&c.subject, &c.issuer] {
            assert!(!s.contains(OVERRIDE) && !s.contains(ZERO_WIDTH), "{s:?}");
        }
    }
    clean(&all_text(&tls_findings_at("example.test", 443, &r, NOW)), "Evil\u{fffd}CA\u{fffd}Ltd");
}

#[test]
fn pasted_email_headers() {
    let a = analyse_headers(
        "Return-Path: <x@evil\u{202e}.test\u{200b}>\nFrom: a@ex.com\nAuthentication-Results: mx; spf=fail smtp.mailfrom=x@evil\u{202e}.test\u{200b}",
    )
    .unwrap();
    clean(&all_text(&header_findings(&a)), "evil\u{fffd}.test\u{fffd}");
}

#[test]
fn pasted_mail_log() {
    let a = analyse_maillog(
        "postfix/smtp[1]: DEC0DE01: to=<u@x.test>, relay=mx[198.51.100.5]:25, dsn=5.1.1, status=bounced (550 User\u{202e} unknown\u{200b})",
    )
    .unwrap();
    clean(&all_text(&maillog_findings(&a)), "User\u{fffd} unknown\u{fffd}");
}

#[test]
fn web_server_header() {
    let r = untrusted::web_page("Server: nginx\u{202e}1\u{200b}.0\nContent-Type: text/html", b"<title>T</title>");
    let server = r.server.as_deref().unwrap();
    assert!(!server.contains(OVERRIDE) && !server.contains(ZERO_WIDTH), "{server:?}");
    assert!(server.contains("nginx"), "{server:?}");
    let fs = web_findings("https://example.com/", &r);
    let text = all_text(&fs);
    assert!(!text.contains(OVERRIDE) && !text.contains(ZERO_WIDTH), "{text:?}");
}

#[test]
fn web_redirect_location() {
    let r = untrusted::web_page("Location: https://exa\u{202e}mple.com/\u{200b}x", b"");
    for hop in &r.chain {
        let text = format!("{} {:?}", hop.url, hop.location);
        assert!(!text.contains(OVERRIDE) && !text.contains(ZERO_WIDTH), "{text:?}");
    }
}

#[test]
fn release_notes() {
    let shown = notes_preview("Fixes\u{202e} a\u{200b} bug\n\u{2028}more");
    assert_eq!(shown, "Fixes a bug more");
}
