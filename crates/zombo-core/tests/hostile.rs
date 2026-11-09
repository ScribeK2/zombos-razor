#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! Hostile input for every parser of untrusted bytes: huge lengths, compression
//! loops, NUL and control characters, invalid UTF-8 and truncation. Each case
//! must return, without a panic, within `BUDGET`.

use std::time::{Duration, Instant, SystemTime};

use zombo_core::{
    dnssec::{Dnskey, Ds, Rrsig},
    email_auth::{
        parse_bimi, parse_dkim_key, parse_dmarc, parse_mta_sts, parse_selectors, parse_spf, parse_tls_rpt, spf_records,
    },
    evidence::{
        headers::{analyse_headers, header_findings},
        maillog::{analyse_maillog, decode_reason, maillog_findings},
    },
    resolver::{parse_addr, parse_resolv_conf},
    smtp::{Extensions, banner_host, valid_ehlo_name},
    target::parse_target,
    untrusted,
    web::{parse_web_target, web_findings},
};

const BUDGET: Duration = Duration::from_secs(5);
const MIB: usize = 1 << 20;

fn bounded<T>(what: &str, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    let took = start.elapsed();
    assert!(took < BUDGET, "{what} took {took:?}");
    out
}

fn no_controls(findings: &[zombo_core::Finding]) {
    for f in findings {
        for s in [f.title.as_ref(), f.message.as_str()] {
            assert!(!s.chars().any(|c| c.is_control() && c != '\n'), "control character in {s:?}");
        }
    }
}

/// Text built to hurt: every shape the parsers have to survive as one string each.
fn nasty_texts() -> Vec<String> {
    let nul = "a\0b\0\0".to_string();
    let controls: String = (0u8..32).map(char::from).collect::<String>() + "\u{7f}\u{85}\u{202e}\u{feff}";
    vec![
        String::new(),
        " ".repeat(1000),
        "\n".repeat(100_000),
        "\r".repeat(100_000),
        nul,
        controls,
        "a".repeat(MIB),
        "=".repeat(100_000),
        ":".repeat(100_000),
        "%{".repeat(100_000),
        "v=spf1 ".to_string() + &"include:a.example ".repeat(50_000),
        "v=spf1 ".to_string() + &"a:".repeat(100_000),
        "v=spf1 ".to_string() + &"+".repeat(100_000),
        "v=spf1 ip4:".to_string() + &"9".repeat(100_000),
        "v=spf1 ip6:".to_string() + &":".repeat(100_000),
        "v=DMARC1; ".to_string() + &"p=none; ".repeat(100_000),
        "v=DKIM1; k=rsa; p=".to_string() + &"A".repeat(MIB),
        "v=DKIM1; p=====".to_string(),
        "v=DKIM1; p=\u{ff}\u{fe}\u{fd}".to_string(),
        "v=STSv1; ".to_string() + &"mx:a;".repeat(100_000),
        "\u{fffd}".repeat(100_000),
        "😀".repeat(100_000),
        "xn--".repeat(10_000),
        "a.".repeat(100_000),
        "[".repeat(100_000),
        "@".repeat(100_000),
        "user@".to_string() + &"a.".repeat(50_000),
        "http://".to_string() + &"a".repeat(MIB),
        "http://[::".to_string(),
        "http://0x7f.1/".to_string(),
        "::ffff:1.2.3.4".to_string(),
        "1.2.3.4.5".to_string(),
        "999.999.999.999".to_string(),
    ]
}

#[test]
fn txt_parsers_survive_nasty_text() {
    for t in nasty_texts() {
        let lines: Vec<String> = t.lines().take(256).map(str::to_string).collect();
        bounded("txt parsers", || {
            let _ = spf_records(&lines);
            let _ = parse_spf("example.com", &t);
            let _ = parse_dmarc(&t);
            let _ = parse_dkim_key("sel", None, &t);
            let _ = parse_dkim_key("sel", Some("sel.provider.example"), &t);
            let _ = parse_tls_rpt(&lines);
            let _ = parse_bimi(&lines);
            let _ = parse_mta_sts(&lines);
            let _ = parse_selectors(&lines);
            let _ = parse_selectors(std::slice::from_ref(&t));
        });
    }
}

#[test]
fn an_spf_record_with_fifty_thousand_terms_is_cut_not_walked() {
    let record = "v=spf1 ".to_string() + &"include:a.example ".repeat(50_000);
    let parsed = bounded("spf", || parse_spf("example.com", &record));
    assert!(parsed.terms.len() <= 1024, "{} terms kept", parsed.terms.len());
    assert!(!parsed.errors.is_empty());
}

#[test]
fn an_equals_sign_after_a_colon_or_slash_does_not_make_a_modifier() {
    use zombo_core::email_auth::Mechanism;
    // "a:foo=bar" is the `a` mechanism with a strange domain; only `name=value` is a modifier.
    let parsed = parse_spf("example.com", "v=spf1 a:foo=bar ip4:192.0.2.0/24 redirect=other.example exp=x.example");
    let kinds: Vec<&Mechanism> = parsed.terms.iter().map(|t| &t.mechanism).collect();
    assert!(matches!(kinds.first(), Some(Mechanism::A(_))), "{kinds:?}");
    assert!(matches!(kinds.get(1), Some(Mechanism::Ip4(..))), "{kinds:?}");
    assert!(matches!(kinds.get(2), Some(Mechanism::Redirect(r)) if r == "other.example"), "{kinds:?}");
    assert!(matches!(kinds.get(3), Some(Mechanism::Exp(_))), "{kinds:?}");
}

#[test]
fn target_and_name_parsers_survive_nasty_text() {
    for t in nasty_texts() {
        bounded("target parsers", || {
            let _ = parse_target(&t);
            let _ = parse_web_target(&t);
            let _ = zombo_core::registration::registrable_domain(&t);
            let _ = valid_ehlo_name(&t);
            let _ = parse_addr(&t);
            let _ = parse_resolv_conf(&t);
            let _ = banner_host(&t);
            let _ = untrusted::banner(t.as_bytes());
        });
    }
}

#[test]
fn smtp_extensions_survive_many_and_long_lines() {
    for t in nasty_texts() {
        let lines: Vec<String> = t.lines().take(100_000).map(str::to_string).collect();
        let ext = bounded("ehlo", || Extensions::parse(&lines));
        assert!(ext.other.len() < 1000, "{} other keywords kept", ext.other.len());
    }
    let long = vec!["AUTH ".to_string() + &"X ".repeat(MIB / 2), "SIZE 99999999999999999999999999".into()];
    bounded("ehlo auth", || Extensions::parse(&long));
}

#[test]
fn evidence_parsers_survive_nasty_text() {
    let mut texts = nasty_texts();
    texts.push("Received: ".repeat(100_000));
    texts.push("Received: from a by b\n".repeat(100_000));
    texts.push("Received: from a by b\n ".to_string() + &" continued\n ".repeat(100_000));
    texts.push("Authentication-Results: ".to_string() + &"spf=pass dkim=pass ".repeat(50_000));
    texts.push("From: ".to_string() + &"<".repeat(100_000));
    texts.push("Subject: =?utf-8?B?".to_string() + &"A".repeat(MIB) + "?=");
    texts.push("Jan  1 00:00:00 h postfix/smtp[1]: ABCDEF: to=<a@b>, status=sent\n".repeat(100_000));
    texts.push("postfix/qmgr[1]: ".repeat(100_000));
    texts.push(
        (0..50_000).map(|i| format!("Jan  1 00:00:00 h postfix/smtp[1]: Q{i:06}: from=<a@b>, size=1\n")).collect(),
    );
    for t in texts {
        bounded("headers", || {
            if let Ok(a) = analyse_headers(&t) {
                no_controls(&header_findings(&a));
            }
        });
        bounded("maillog", || {
            if let Ok(a) = analyse_maillog(&t) {
                no_controls(&maillog_findings(&a));
            }
        });
        bounded("decode_reason", || decode_reason(&t, &t));
    }
}

fn name(labels: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![];
    for l in labels {
        out.push(l.len() as u8);
        out.extend_from_slice(l);
    }
    out.push(0);
    out
}

fn header(id: u16, qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
    let mut h = id.to_be_bytes().to_vec();
    for n in [0x8180, qd, an, ns, ar] {
        h.extend_from_slice(&u16::to_be_bytes(n));
    }
    h
}

#[test]
fn dns_messages_survive_loops_huge_counts_and_truncation() {
    let mut cases: Vec<Vec<u8>> = vec![vec![], vec![0; 11], vec![0xff; 12], header(1, 0xffff, 0xffff, 0xffff, 0xffff)];
    // A question name that points at itself, and one that points forward.
    let mut selfloop = header(1, 1, 0, 0, 0);
    selfloop.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
    cases.push(selfloop);
    let mut pair = header(1, 1, 0, 0, 0);
    pair.extend_from_slice(&[0xc0, 14, 0xc0, 12, 0, 1, 0, 1]);
    cases.push(pair);
    let mut forward = header(1, 1, 0, 0, 0);
    forward.extend_from_slice(&[0xc0, 0xff, 0, 1, 0, 1]);
    cases.push(forward);
    // An answer whose rdata length runs past the end, and a CNAME that points at its own owner.
    let mut long_rdata = header(1, 1, 1, 0, 0);
    long_rdata.extend(name(&[b"a"]));
    long_rdata.extend_from_slice(&[0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0xff, 0xff, 1, 2]);
    cases.push(long_rdata);
    let mut cname = header(1, 1, 1, 0, 0);
    cname.extend(name(&[b"a"]));
    cname.extend_from_slice(&[0, 5, 0, 1, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 1, 0, 2, 0xc0, 12]);
    cases.push(cname);
    // A 63 byte label cut short, and 255 bytes of labels.
    let mut cut = header(1, 1, 0, 0, 0);
    cut.push(63);
    cut.extend_from_slice(b"abc");
    cases.push(cut);
    let mut longname = header(1, 1, 0, 0, 0);
    longname.extend(name(&[&[b'a'; 63], &[b'b'; 63], &[b'c'; 63], &[b'd'; 63], &[b'e'; 10]]));
    longname.extend_from_slice(&[0, 1, 0, 1]);
    cases.push(longname);
    // NULs and control bytes inside labels.
    let mut nul = header(1, 1, 0, 0, 0);
    nul.extend(name(&[b"a\0b", b"\x01\x02", b"c d"]));
    nul.extend_from_slice(&[0, 1, 0, 1]);
    cases.push(nul);
    // Every prefix of a good message.
    let mut good = header(7, 1, 1, 0, 0);
    good.extend(name(&[b"example", b"com"]));
    good.extend_from_slice(&[0, 16, 0, 1, 0xc0, 12, 0, 16, 0, 1, 0, 0, 1, 44, 0, 6, 5, b'h', b'e', b'l', b'l', b'o']);
    cases.extend((0..good.len()).map(|n| good[..n].to_vec()));
    cases.push(good);
    for c in cases {
        bounded("dns message", || untrusted::dns_message(&c));
    }
    for seed in 0..2000u64 {
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let c: Vec<u8> = (0..(seed % 300))
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect();
        bounded("random dns message", || untrusted::dns_message(&c));
    }
}

#[test]
fn dnssec_rdata_survives_every_length_and_hostile_names() {
    let mut cases: Vec<Vec<u8>> = (0..64).map(|n| vec![0xff; n]).collect();
    cases.extend((0..64).map(|n| vec![0; n]));
    cases.push(vec![0xff; 4 * MIB]);
    cases.push(vec![0; 4 * MIB]);
    let mut sig = vec![0u8; 18];
    sig.extend(vec![63u8; 1]);
    sig.extend(vec![b'a'; 63]);
    cases.push(sig.clone());
    sig.push(0xc0);
    sig.push(0);
    cases.push(sig);
    let mut labels = vec![0u8; 18];
    for _ in 0..10_000 {
        labels.extend_from_slice(&[1, b'a']);
    }
    cases.push(labels);
    for c in cases {
        bounded("dnssec rdata", || {
            if let Some(s) = Rrsig::from_rdata(&c) {
                let _ = s.window(SystemTime::UNIX_EPOCH);
                let _ = s.window(SystemTime::now());
            }
            let _ = Ds::from_rdata(&c);
            let _ = Dnskey::from_rdata(&c);
        });
    }
}

fn nested(depth: usize, open: &str, close: &str) -> String {
    open.repeat(depth) + &close.repeat(depth)
}

#[test]
fn rdap_json_survives_depth_wrong_shapes_and_junk() {
    let mut cases: Vec<Vec<u8>> = vec![
        vec![],
        b"null".to_vec(),
        b"[]".to_vec(),
        b"{}".to_vec(),
        vec![0xff, 0xfe, 0x00],
        br#"{"status":null,"events":null,"nameservers":null,"entities":null}"#.to_vec(),
        br#"{"status":"active"}"#.to_vec(),
        br#"{"events":[{"eventAction":1}]}"#.to_vec(),
        br#"{"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["fn"],["fn",{},"text"],["fn",{},"text",5],[]]]}]}"#.to_vec(),
        br#"{"entities":[{"roles":["registrar"],"vcardArray":"x"}]}"#.to_vec(),
        br#"{"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["fn",{},"text","Evil\u0000\u001b[2J\u202e Inc"]]]}],"status":["a\u0000b"],"events":[{"eventAction":"expiration","eventDate":"x\u001b[2Jy"}]}"#.to_vec(),
        br#"{"entities":[{"roles":["registrar"],"vcardArray":["vcard",5]}]}"#.to_vec(),
        br#"{"status":["clientHold https://icann.org/epp#clientHold"],"events":[{"eventAction":"expiration","eventDate":"\u0000\u202e"}]}"#.to_vec(),
        br#"{"nameservers":[{"ldhName":"a\u0000.example.\u001b[2J"}]}"#.to_vec(),
        br#"{"secureDNS":{"delegationSigned":"yes"}}"#.to_vec(),
        nested(100_000, "[", "]").into_bytes(),
        nested(100_000, "{\"a\":", "}").into_bytes(),
        format!(r#"{{"status":["{}"]}}"#, "a ".repeat(MIB / 2)).into_bytes(),
        format!(r#"{{"nameservers":[{}]}}"#, r#"{"ldhName":"ns.example"},"#.repeat(40_000) + r#"{"ldhName":"x"}"#).into_bytes(),
        format!(r#"{{"events":[{}]}}"#, r#"{"eventAction":"expiration","eventDate":"9999999999999999-01-01"},"#.repeat(20_000) + "{}").into_bytes(),
        b"{\"a\":1e999999999,\"b\":-0,\"c\":123456789012345678901234567890}".to_vec(),
    ];
    let good = br#"{"status":["active"],"events":[{"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"}],"nameservers":[{"ldhName":"NS1.EXAMPLE.COM."}]}"#;
    cases.extend((0..good.len()).map(|n| good[..n].to_vec()));
    for c in cases {
        bounded("rdap", || no_controls(&untrusted::rdap(&c)));
    }
}

#[test]
fn whois_text_survives_nasty_text() {
    let mut texts = nasty_texts();
    texts.push("Registrar: ".repeat(100_000));
    texts.push("Registrar:\n".repeat(100_000));
    texts.push("Registrar: a\u{1b}[31m\0\u{202e}b\nStatus: ACTIVE https://x\nName Server: n\u{7}s\n".repeat(1000));
    texts.push("[Registrar]\n".to_string() + &"x\n".repeat(MIB / 2));
    texts.push("Creation Date: 9999-99-99T99:99:99Z\nExpiry Date: 0000-00-00\nUpdated: \u{0}\n".repeat(10_000));
    texts.push("Domain: a\nStatus: ".to_string() + &"free ".repeat(100_000));
    for t in texts {
        bounded("whois", || no_controls(&untrusted::whois(&t)));
    }
}

fn run<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap().block_on(f)
}

#[test]
fn smtp_replies_survive_long_lines_endless_continuations_and_junk() {
    let long = format!("250 {}\r\n", "x".repeat(MIB));
    let endless = "250-more\r\n".repeat(100_000);
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        b"\r\n".to_vec(),
        b"2".to_vec(),
        b"250".to_vec(),
        b"250 ok".to_vec(),
        b"999 nope\r\n".to_vec(),
        b"099 nope\r\n".to_vec(),
        b"250x ok\r\n".to_vec(),
        b"abc def\r\n".to_vec(),
        b"250-a\r\n251 b\r\n".to_vec(),
        b"250 a\0b\x1b[2J\x07\r\n".to_vec(),
        b"250 \xff\xfe\xfd\r\n".to_vec(),
        b"\0".repeat(MIB),
        long.into_bytes(),
        endless.into_bytes(),
        b"250 ok\r\n".repeat(100_000),
        b"220 a\r\n\xff\xff\xff".to_vec(),
    ];
    for c in cases {
        bounded("smtp reply", || run(untrusted::smtp_replies(c)));
    }
}

#[test]
fn web_responses_survive_hostile_headers_and_redirects() {
    let heads = [
        String::new(),
        "Location: javascript:alert(1)\n".into(),
        "Location: file:///etc/passwd\n".into(),
        "Location: data:text/html,x\n".into(),
        "Location: //evil.example\n".into(),
        "Location: http://[::1\n".into(),
        "Location: ?\u{0}\n".into(),
        format!("Location: http://{}/\n", "a".repeat(MIB)),
        "Location: /a\n".repeat(100_000),
        "Server: a\u{0}b\u{1b}[2J\n".into(),
        format!("Server: {}\n", "x".repeat(MIB)),
        "\u{0}: \u{0}\nStrict-Transport-Security\n:\n::::\n".into(),
        "Content-Security-Policy: frame-ancestors ;;;;; ".repeat(10_000),
        "X-Frame-Options:\nContent-Security-Policy: ".to_string() + &"frame-ancestors a;".repeat(100_000),
        "Server: cloudflare\nVia: 1.1 varnish\nX-Powered-By: PHP/\u{0}\nSet-Cookie: a=b\n".into(),
    ];
    let bodies: Vec<Vec<u8>> = vec![
        vec![],
        vec![0; MIB],
        vec![0xff; MIB],
        b"<meta name=\"generator\" content=\"WordPress ".repeat(50_000),
        b"<meta name=\"generator\" content=\"WordPress 6.\x00\xff\">".to_vec(),
        b"There has been a critical error on this website".repeat(10_000),
        b"<meta name='generator' content='".to_vec(),
    ];
    for h in &heads {
        for b in &bodies {
            bounded("web page", || {
                let r = untrusted::web_page(h, b);
                no_controls(&web_findings("example.com", &r));
            });
        }
    }
}

const PEM: &str = include_str!("../../../testdata/tls/weak-rsa1024-sha1.pem");

fn der() -> Vec<u8> {
    let b64: String = PEM.lines().filter(|l| !l.starts_with("-----")).collect();
    data_encoding::BASE64.decode(b64.as_bytes()).unwrap()
}

fn chain_of(certs: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![];
    for c in certs {
        out.extend_from_slice(&(c.len() as u16).to_be_bytes());
        out.extend_from_slice(c);
    }
    out
}

#[test]
fn certificates_survive_truncation_bit_flips_and_ber_tricks() {
    let good = der();
    let mut cases: Vec<Vec<u8>> = vec![
        vec![],
        chain_of(&[&[]]),
        chain_of(&[&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]]),
        chain_of(&[&[0x30, 0x80, 0x00, 0x00]]),
        chain_of(&[&[0x30, 0x03, 0x02, 0x01, 0x00]]),
        chain_of(&[&vec![0x30; 70_000]]),
        chain_of(&vec![&good[..]; 20]),
        chain_of(&[&good, &[0xff; 100], &good]),
    ];
    cases.extend((0..good.len()).step_by(7).map(|n| chain_of(&[&good[..n]])));
    for i in (0..good.len()).step_by(5) {
        for flip in [0x01u8, 0x80, 0xff] {
            let mut bad = good.clone();
            bad[i] ^= flip;
            cases.push(chain_of(&[&bad]));
        }
    }
    cases.push(chain_of(&[&good]));
    for c in cases {
        bounded("certificate", || no_controls(&untrusted::tls_chain(&c)));
    }
}

fn testdata_files() -> Vec<(String, Vec<u8>)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
    let mut out = vec![];
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(b) = std::fs::read(&p) {
                out.push((p.display().to_string(), b));
            }
        }
    }
    out.sort();
    out
}

/// A fixed-seed mutation loop over the repo's own fixtures: a stable-toolchain stand-in for a fuzzer that always runs.
#[test]
fn mutated_fixtures_never_panic_in_any_parser() {
    let mut x: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let start = Instant::now();
    for (path, bytes) in testdata_files() {
        if bytes.len() > 256 * 1024 {
            continue;
        }
        for round in 0..40 {
            let mut b = bytes.clone();
            for _ in 0..=(round % 8) {
                if b.is_empty() {
                    break;
                }
                let at = (next() as usize) % b.len();
                match next() % 4 {
                    0 => b[at] ^= 1 << (next() % 8),
                    1 => b[at] = (next() & 0xff) as u8,
                    2 => b.truncate(at),
                    _ => {
                        let take = ((next() as usize) % 64).min(b.len() - at);
                        let chunk = b[at..at + take].to_vec();
                        b.splice(at..at, chunk);
                    }
                }
            }
            let text = String::from_utf8_lossy(&b).into_owned();
            let lines: Vec<String> = text.lines().take(256).map(str::to_string).collect();
            let _ = (&path, &lines);
            let _ = spf_records(&lines);
            let _ = parse_spf("example.com", &text);
            let _ = parse_dmarc(&text);
            let _ = parse_dkim_key("s", None, &text);
            let _ = parse_target(&text);
            if let Ok(a) = analyse_headers(&text) {
                no_controls(&header_findings(&a));
            }
            if let Ok(a) = analyse_maillog(&text) {
                no_controls(&maillog_findings(&a));
            }
            no_controls(&untrusted::rdap(&b));
            no_controls(&untrusted::whois(&text));
            let _ = untrusted::dns_message(&b);
            no_controls(&untrusted::tls_chain(&b));
            let head_end = b.iter().position(|&c| c == 0).unwrap_or(b.len() / 2);
            let r = untrusted::web_page(&String::from_utf8_lossy(&b[..head_end]), &b[head_end..]);
            no_controls(&web_findings("example.com", &r));
        }
    }
    assert!(start.elapsed() < Duration::from_secs(120), "mutation loop took {:?}", start.elapsed());
}
