#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! Header analysis: the Go scenarios, plus hostile input.

#[path = "common/evidence.rs"]
mod evidence;

use std::time::{Duration, Instant};

/// A guard against a hang or a quadratic parser, not a speed test: these tests run in an unoptimized
/// debug build on shared CI runners, where 60,000 lines legitimately take seconds.
const HANG_GUARD: Duration = Duration::from_secs(30);

use evidence::fixture;
use zombo_core::{
    Severity,
    evidence::{
        EvidenceError, MAX_INPUT,
        headers::{Anomaly, HeaderAnalysis, Verdict, analyse_headers, header_findings},
    },
};

fn analyse(raw: &str) -> HeaderAnalysis {
    analyse_headers(raw).unwrap_or_else(|e| panic!("{e}"))
}

fn codes(a: &HeaderAnalysis) -> Vec<&'static str> {
    header_findings(a).iter().map(|f| f.code).collect()
}

fn ip(s: &str) -> Option<std::net::IpAddr> {
    s.parse().ok()
}

#[test]
fn pasted_headers_are_analysed() {
    let a = analyse(&fixture("gmail.txt"));
    assert_eq!(a.origin_ip, ip("203.0.113.5"));
    assert_eq!(a.delivering_ip, ip("209.85.220.41"));
    assert_eq!(a.hops.len(), 2);
    assert_eq!(a.auth.dmarc, Some(Verdict::Pass));
    assert_eq!(a.headers.subject, "Hello");
    assert_eq!(a.alignment.dkim_domain, "example.com");
    let f = header_findings(&a);
    let ok = f.iter().find(|f| f.code == "email_headers_authenticated").map(|f| f.severity);
    assert_eq!(ok, Some(Severity::Ok), "{f:?}");
    // The hosts and addresses of the chain are exposed for later lookups.
    assert!(a.extracted.ips.contains(&"209.85.220.41".parse().unwrap()));
    assert!(a.extracted.hosts.contains(&"mail-sor-f41.google.com".to_string()));
}

#[test]
fn spoofed_headers_are_called_out() {
    let a = analyse(&fixture("spoofed.txt"));
    assert_eq!(a.auth.dmarc, Some(Verdict::Fail));
    assert_eq!(a.alignment.from_domain, "yourbank.test");
    assert_eq!(a.alignment.return_path_domain, "evil.test");
    assert_eq!(a.alignment.from_return_path_aligned, Some(false));
    assert_eq!(a.origin_ip, ip("198.51.100.66"));
    let c = codes(&a);
    for want in ["email_headers_dmarc_fail", "email_headers_spf_fail", "email_headers_misaligned"] {
        assert!(c.contains(&want), "missing {want} in {c:?}");
    }
    for f in header_findings(&a) {
        match f.code {
            "email_headers_dmarc_fail" | "email_headers_spf_fail" => {
                assert_eq!(f.severity, Severity::Critical, "{}", f.code)
            }
            "email_headers_misaligned" => assert_eq!(f.severity, Severity::Warning),
            _ => {}
        }
    }
    // dkim=none is a warning with its own title.
    let dkim = header_findings(&a).into_iter().find(|f| f.code == "email_headers_dkim_fail");
    assert_eq!(dkim.map(|f| f.title.into_owned()), Some("Not DKIM-signed".to_string()));
}

#[test]
fn minimal_headers_have_no_authentication_verdict() {
    let a = analyse(&fixture("minimal.txt"));
    assert!(a.hops.is_empty() && a.auth.spf.is_none() && a.origin_ip.is_none());
    assert!(codes(&a).contains(&"email_headers_no_auth_results"));
}

#[test]
fn quoted_folded_headers_ignore_the_body() {
    let a = analyse(
        "> From: Alice <alice@ex.com>\n> Subject: multi\n>  line subject\n> X-Body-Should-Be: ignored\n\nThis is the body and must be ignored.\nReceived: should not be parsed from body",
    );
    assert_eq!(a.headers.from, "Alice <alice@ex.com>");
    assert_eq!(a.headers.subject, "multi line subject");
    assert!(a.hops.is_empty());
}

#[test]
fn hops_read_oldest_first_with_delays() {
    let a = analyse(
        "Received: from relay.ex.com (relay.ex.com [203.0.113.9]) by mx.dest.com with ESMTPS id Z2; Wed, 14 Jun 2026 10:02:00 -0700\nReceived: from sender.ex.com (sender.ex.com [203.0.113.5]) by relay.ex.com with ESMTP id Z1 for <u@dest.com>; Wed, 14 Jun 2026 10:00:00 -0700\nFrom: a@ex.com",
    );
    assert_eq!(a.hops.len(), 2);
    assert_eq!(
        (a.hops[0].from_host.as_str(), a.hops[0].from_ip, a.hops[0].with.as_str()),
        ("sender.ex.com", ip("203.0.113.5"), "ESMTP")
    );
    assert_eq!(a.hops[0].by_host, "relay.ex.com");
    assert_eq!((a.hops[0].delay_s, a.hops[1].delay_s, a.total_transit_s), (None, Some(120), Some(120)));
}

#[test]
fn private_and_ula_hops_are_not_the_origin() {
    let a = analyse(
        "Received: from a (a [203.0.113.7]) by mx; Wed, 14 Jun 2026 10:01:00 -0700\nReceived: from v6 (v6 [IPv6:fd00::1]) by a; Wed, 14 Jun 2026 10:00:30 -0700\nReceived: from localhost (localhost [127.0.0.1]) by v6; Wed, 14 Jun 2026 10:00:00 -0700\nFrom: a@ex.com",
    );
    assert_eq!(a.origin_ip, ip("203.0.113.7"));
    assert_eq!(a.delivering_ip, ip("203.0.113.7"));
}

#[test]
fn a_long_delay_between_hops_is_flagged() {
    let a = analyse(
        "Received: from relay (relay [203.0.113.9]) by mx; Wed, 14 Jun 2026 10:45:00 -0700\nReceived: from sender (sender [203.0.113.5]) by relay; Wed, 14 Jun 2026 10:00:00 -0700\nFrom: a@ex.com",
    );
    let f = header_findings(&a).into_iter().find(|f| f.code == "email_headers_delayed").expect("delayed");
    assert_eq!(f.message, "It waited 45 minutes between relay and mx.");
    assert_eq!(f.severity, Severity::Warning);
}

#[test]
fn relaxed_alignment_and_a_spam_score() {
    let a = analyse(
        "Return-Path: <bounce@mailer.ex.com>\nFrom: \"Brand\" <noreply@ex.com>\nMessage-ID: <abc.123@ex.com>\nX-Spam-Score: 7.4\nDate: Wed, 14 Jun 2026 10:00:00 -0700",
    );
    assert_eq!((a.alignment.from_return_path_aligned, a.alignment.message_id_aligned), (Some(true), Some(true)));
    assert_eq!(a.spam.score, Some(7.4));
    assert!(a.spam.flagged);
    let f = header_findings(&a).into_iter().find(|f| f.code == "email_headers_spam").expect("spam");
    assert_eq!(f.message, "The receiving side marked this message as spam (score 7.4).");
}

#[test]
fn microsoft_scl_flags_spam() {
    let a = analyse("From: a@ex.com\nX-MS-Exchange-Organization-SCL: 6");
    assert!(a.spam.flagged);
    assert_eq!(a.spam.scl, Some(6));
    let low = analyse("From: a@ex.com\nX-Forefront-Antispam-Report: CIP:1.2.3.4;SCL:1;SFV:NSPM");
    assert_eq!((low.spam.scl, low.spam.flagged), (Some(1), false));
}

#[test]
fn spamassassin_status_uses_its_own_threshold() {
    let a = analyse("From: a@ex.com\nX-Spam-Status: No, score=6.0 required=8.0 tests=FOO");
    assert_eq!((a.spam.score, a.spam.required, a.spam.flagged), (Some(6.0), Some(8.0), false));
    let b = analyse("From: a@ex.com\nX-Spam-Status: Yes, score=1.0 required=8.0 tests=FOO");
    assert!(b.spam.flagged);
}

#[test]
fn text_that_is_not_headers_is_refused() {
    for raw in ["just some random text\nno colons here", "   ", ""] {
        assert_eq!(analyse_headers(raw).err(), Some(EvidenceError::NotThisKind("email headers")), "{raw:?}");
    }
    let e = analyse_headers("nothing here").err().map(|e| e.to_string());
    assert_eq!(e.as_deref(), Some("this doesn't look like email headers: no recognisable content"));
}

#[test]
fn a_failed_dkim_signature_does_not_count_as_aligned() {
    let a = analyse(
        "Received: from sketchy.host (sketchy.host [198.51.100.66]) by mx.dest.com with ESMTP; Wed, 14 Jun 2026 03:00:00 +0000\nAuthentication-Results: mx.dest.com; spf=fail smtp.mailfrom=evil.test; dkim=fail header.d=yourbank.test; dmarc=fail header.from=yourbank.test\nDKIM-Signature: v=1; a=rsa-sha256; d=yourbank.test; s=forged; b=AAAA\nReturn-Path: <attacker@evil.test>\nFrom: Your Bank <security@yourbank.test>",
    );
    assert_eq!(a.alignment.from_return_path_aligned, Some(false));
    assert_eq!(a.alignment.dkim_domain, "");
    assert!(codes(&a).contains(&"email_headers_misaligned"));
    // The signature is still listed as written.
    assert_eq!(
        (a.auth.dkim_signatures[0].domain.as_str(), a.auth.dkim_signatures[0].selector.as_str()),
        ("yourbank.test", "forged")
    );
}

#[test]
fn the_delivering_server_is_known_apart_from_the_claimed_origin() {
    let a = analyse(
        "Received: from relay.spam.test (relay.spam.test [198.51.100.66]) by mx.dest.com with ESMTP; Wed, 14 Jun 2026 03:00:05 +0000\nReceived: from innocent (innocent [8.8.8.8]) by relay.spam.test; Wed, 14 Jun 2026 03:00:00 +0000\nFrom: a@spam.test",
    );
    assert_eq!(a.delivering_ip, ip("198.51.100.66"));
    assert_eq!(a.origin_ip, ip("8.8.8.8"));
}

#[test]
fn a_verified_dkim_pass_aligns_by_its_signing_domain() {
    let a = analyse(
        "Authentication-Results: mx; dkim=pass header.i=@news.ex.com\nReturn-Path: <b@other.test>\nFrom: a@ex.com",
    );
    assert_eq!((a.alignment.dkim_domain.as_str(), a.alignment.dkim_aligned), ("news.ex.com", Some(true)));
    assert!(!codes(&a).contains(&"email_headers_misaligned"));
}

#[test]
fn received_spf_stands_in_for_a_missing_spf_verdict() {
    let a = analyse("Received-SPF: softfail (domain owner discourages use) client-ip=1.2.3.4\nFrom: a@ex.com");
    assert_eq!(a.auth.spf, Some(Verdict::Softfail));
    let f = header_findings(&a).into_iter().find(|f| f.code == "email_headers_spf_fail").expect("spf");
    assert_eq!((f.severity, f.title.as_ref()), (Severity::Warning, "SPF softfail"));
    // The Authentication-Results verdict wins when both are present.
    let b = analyse("Received-SPF: fail\nAuthentication-Results: mx; spf=pass\nFrom: a@ex.com");
    assert_eq!(b.auth.spf, Some(Verdict::Pass));
}

#[test]
fn unknown_verdict_words_are_kept() {
    let a = analyse("Authentication-Results: mx; dmarc=bestguesspass; spf=pass\nFrom: a@ex.com");
    assert_eq!(a.auth.dmarc, Some(Verdict::Other("bestguesspass".into())));
    let f = header_findings(&a).into_iter().find(|f| f.code == "email_headers_dmarc_none").expect("dmarc");
    assert_eq!((f.severity, f.title.as_ref()), (Severity::Info, "No DMARC verdict (bestguesspass)"));
    let json = serde_json::to_value(&a.auth).unwrap_or_default();
    assert_eq!(json["dmarc"], "bestguesspass");
    assert_eq!(json["spf"], "pass");
}

#[test]
fn dates_tolerate_comments_named_zones_and_a_missing_weekday() {
    let a = analyse(
        "Received: from b (b [203.0.113.9]) by mx; 14 Jun 2026 17:02 GMT\nReceived: from a (a [203.0.113.5]) by b; Wed, 14 Jun 2026 10:00:00 -0700 (PDT)\nFrom: a@ex.com",
    );
    assert_eq!((a.hops[1].delay_s, a.total_transit_s), (Some(120), Some(120)));
    let c = analyse("Received: from a (a [203.0.113.5]) by b; Wed, 14 Jun 2026 10:00:00 PDT\nFrom: a@ex.com");
    assert!(c.hops[0].at.is_some());
    let bad = analyse("Received: from a (a [203.0.113.5]) by b; yesterday-ish\nFrom: a@ex.com");
    assert!(bad.hops[0].at.is_none());
    let json = serde_json::to_value(&a.hops[0]).unwrap_or_default();
    assert_eq!(json["at"], "2026-06-14T10:00:00-07:00");
}

#[test]
fn hops_dated_backwards_are_an_anomaly() {
    let a = analyse(
        "Received: from b (b [203.0.113.9]) by mx; Wed, 14 Jun 2026 10:00:00 +0000\nReceived: from a (a [203.0.113.5]) by b; Wed, 14 Jun 2026 11:00:00 +0000\nFrom: a@ex.com",
    );
    assert!(a.anomalies.contains(&Anomaly::ClockSkew { hop: 1 }));
    assert!(codes(&a).contains(&"email_headers_clock_skew"));
}

#[test]
fn two_from_headers_are_an_anomaly() {
    let a = analyse("From: a@ex.com\nFrom: b@evil.test\nSubject: x");
    assert!(a.anomalies.contains(&Anomaly::MultipleFrom { count: 2 }));
    assert!(codes(&a).contains(&"email_headers_multiple_from"));
}

#[test]
fn a_quoted_display_name_cannot_hide_the_real_address() {
    let a = analyse("From: \"Bob <evil@spoof.test>\" <real@ex.com>\nReturn-Path: <\"x@a.test\"@ex.com>");
    assert_eq!(a.alignment.from_domain, "ex.com");
    assert_eq!(a.alignment.return_path_domain, "ex.com");
    let escaped = analyse("From: \"a\\\"<q@spoof.test>\" <real@ex.com>");
    assert_eq!(escaped.alignment.from_domain, "ex.com");
    let bare = analyse("From: Someone@Example.COM");
    assert_eq!(bare.alignment.from_domain, "example.com");
}

#[test]
fn crlf_pastes_read_the_same() {
    for name in ["gmail.txt", "spoofed.txt", "minimal.txt"] {
        let lf = fixture(name);
        let crlf = lf.replace('\n', "\r\n");
        let (a, b) = (analyse(&lf), analyse(&crlf));
        assert_eq!(serde_json::to_string(&a).ok(), serde_json::to_string(&b).ok(), "{name}");
    }
}

#[test]
fn control_characters_never_reach_a_finding() {
    let a = analyse("Return-Path: <x@evil\u{1b}[31m.test>\nFrom: a@ex.com\nAuthentication-Results: mx; spf=fail");
    for f in header_findings(&a) {
        let text = format!("{} {} {}", f.title, f.message, f.recommendation.unwrap_or_default());
        assert!(!text.chars().any(char::is_control), "{text:?}");
    }
}

#[test]
fn a_megabyte_single_line_is_bounded() {
    let raw = format!("Subject: {}\nFrom: a@ex.com\nReceived: {}", "a".repeat(1 << 20), "from ".repeat(200_000));
    let start = Instant::now();
    let a = analyse(&raw);
    assert!(start.elapsed() < HANG_GUARD, "{:?}", start.elapsed());
    assert!(a.headers.subject.len() <= 16 * 1024);
    assert!(a.anomalies.contains(&Anomaly::Truncated));
    assert!(codes(&a).contains(&"email_headers_truncated"));
}

#[test]
fn a_hundred_thousand_received_headers_are_bounded() {
    let mut raw = String::new();
    for i in 0..100_000 {
        raw.push_str(&format!("Received: from h{i} ([203.0.113.7])\n"));
    }
    raw.push_str("From: a@ex.com\n");
    let start = Instant::now();
    let a = analyse(&raw);
    assert!(start.elapsed() < HANG_GUARD, "{:?}", start.elapsed());
    assert!(raw.len() < MAX_INPUT);
    assert_eq!(a.hops.len(), 250);
    assert!(a.anomalies.contains(&Anomaly::TooManyHops { total: 1000 }));
    assert!(a.anomalies.contains(&Anomaly::Truncated));
    let _ = header_findings(&a);
}

#[test]
fn nested_quote_marks_are_linear() {
    let raw = format!("{}From: a@ex.com\n{}Subject: x", "> ".repeat(4_000), ">".repeat(1 << 20));
    let start = Instant::now();
    let a = analyse(&raw);
    assert!(start.elapsed() < HANG_GUARD, "{:?}", start.elapsed());
    assert_eq!(a.headers.from, "a@ex.com");
}

#[test]
fn hostile_addresses_and_dates_are_bounded() {
    let raw = format!(
        "From: {}\nReturn-Path: {}\nReceived: from {} by {}; {}\nAuthentication-Results: {}",
        "\"".repeat(10_000) + &"<".repeat(10_000),
        "<".repeat(20_000),
        "(".repeat(10_000),
        "[".repeat(10_000),
        "(".repeat(10_000) + "14 Jun 2026",
        "spf=".repeat(4_000),
    );
    let a = analyse(&raw);
    let _ = header_findings(&a);
}

#[test]
fn binary_junk_does_not_panic() {
    let mut x: u32 = 0x1234_5678;
    for round in 0..50 {
        let bytes: Vec<u8> = (0..20_000)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let b = (x >> 24) as u8;
                if round % 2 == 0 && b.is_multiple_of(7) { b':' } else { b }
            })
            .collect();
        let text = String::from_utf8_lossy(&bytes);
        if let Ok(a) = analyse_headers(&text) {
            let _ = header_findings(&a);
        }
    }
    // Junk after a real header is just a value.
    let a = analyse(&format!("From: a@ex.com\nX-Junk: {}", String::from_utf8_lossy(&[0xff, 0xfe, 0x00, 0x1b])));
    assert_eq!(a.headers.from, "a@ex.com");
}

#[test]
fn input_over_four_mebibytes_is_refused() {
    let big = format!("From: a@ex.com\n{}", "X: y\n".repeat(MAX_INPUT / 4));
    assert_eq!(analyse_headers(&big).err(), Some(EvidenceError::TooLarge));
}
