//! The SMTP Check against a scripted server on 127.0.0.1 with throwaway certificates.

#[path = "common/smtp.rs"]
mod fake;
#[path = "common/tls.rs"]
mod pki;

use std::time::{Duration, Instant};

use fake::{FakeSmtp, Step, say};
use pki::{Ca, NOW, days};
use rustls::RootCertStore;
use zombo_core::{
    Finding, Severity,
    smtp::{Mode, Reach, SmtpOptions, SmtpResult, Stage, Starttls, Timing, check_smtp_via, smtp_findings_at},
};

const HOST: &str = "mail.example.test";

fn options(mode: Mode) -> SmtpOptions {
    let mut o = SmtpOptions::for_port(25);
    o.mode = mode;
    o.timing = Timing { connect: Duration::from_secs(2), step: Duration::from_secs(2), overall: Duration::from_secs(6) };
    o
}

async fn run(addr: std::net::SocketAddr, o: &SmtpOptions, roots: &RootCertStore) -> SmtpResult {
    check_smtp_via(addr, HOST, addr.port(), o, roots, NOW).await
}

fn codes(fs: &[Finding]) -> Vec<&'static str> {
    fs.iter().map(|f| f.code).collect()
}

fn server(ca: &Ca, sans: &[&str]) -> std::sync::Arc<rustls::ServerConfig> {
    let leaf = ca.valid_leaf(sans);
    pki::server_config(vec![leaf.der], leaf.key)
}

const EHLO_PLAIN: &str = "250-mail.example.test\r\n250-PIPELINING\r\n250-SIZE 35882577\r\n250-8BITMIME\r\n250 STARTTLS\r\n";

fn starttls_script(ehlo_before: &str, cfg: std::sync::Arc<rustls::ServerConfig>) -> Vec<Step> {
    vec![
        say("220 mail.example.test ESMTP ready\r\n"),
        Step::Expect("EHLO"),
        say(ehlo_before),
        Step::Expect("STARTTLS"),
        say("220 Ready to start TLS\r\n"),
        Step::Tls(cfg),
        Step::Expect("EHLO"),
        say("250-mail.example.test\r\n250-AUTH PLAIN LOGIN\r\n250 PIPELINING\r\n"),
        Step::Expect("QUIT"),
        say("221 bye\r\n"),
    ]
}

#[tokio::test]
async fn the_whole_dialogue_is_read_and_never_sends_mail() {
    let ca = Ca::root("Test Root CA");
    let srv = FakeSmtp::start(starttls_script(EHLO_PLAIN, server(&ca, &[HOST]))).await;
    let r = run(srv.addr, &options(Mode::Starttls), &ca.roots()).await;

    assert_eq!(r.reach, Reach::Answered);
    assert!(r.failure.is_none(), "{:?}", r.failure);
    let b = r.banner.as_ref().unwrap();
    assert_eq!((b.code, b.hostname.as_deref()), (220, Some(HOST)));
    let e = r.extensions.as_ref().unwrap();
    assert!(e.starttls && e.pipelining && e.eight_bit_mime && e.auth.is_empty());
    assert_eq!(e.size, Some(35_882_577));
    assert_eq!(r.starttls, Starttls::Upgraded);
    assert!(r.tls.as_ref().unwrap().verified);
    assert_eq!(r.extensions_after_tls.as_ref().unwrap().auth, ["PLAIN", "LOGIN"]);
    assert_eq!(srv.received(), ["EHLO zombo.invalid", "STARTTLS", "EHLO zombo.invalid", "QUIT"]);

    let fs = smtp_findings_at(&r, &[HOST.to_string()], NOW);
    assert_eq!(codes(&fs), ["ssl_inspection_valid", "smtp_tls_ok"]);
    assert!(fs.iter().all(|f| f.severity == Severity::Ok));
}

#[tokio::test]
async fn auth_offered_before_tls_is_a_warning() {
    let ca = Ca::root("Test Root CA");
    let plain = "250-mail.example.test\r\n250-AUTH PLAIN LOGIN\r\n250 STARTTLS\r\n";
    let srv = FakeSmtp::start(starttls_script(plain, server(&ca, &[HOST]))).await;
    let r = run(srv.addr, &options(Mode::Starttls), &ca.roots()).await;
    let fs = smtp_findings_at(&r, &[], NOW);
    let f = fs.iter().find(|f| f.code == "smtp_auth_before_tls").unwrap();
    assert_eq!(f.severity, Severity::Warning);
    assert!(f.message.contains("PLAIN, LOGIN"), "{}", f.message);
}

#[tokio::test]
async fn a_server_without_starttls_is_flagged_and_quit_politely() {
    let srv = FakeSmtp::start(vec![
        say("220 mail.example.test ESMTP\r\n"),
        Step::Expect("EHLO"),
        say("250-mail.example.test\r\n250 SIZE 1000\r\n"),
        Step::Expect("QUIT"),
        say("221 bye\r\n"),
    ])
    .await;
    let r = run(srv.addr, &options(Mode::Starttls), &RootCertStore::empty()).await;
    assert_eq!(r.starttls, Starttls::NotOffered);
    assert_eq!(srv.received(), ["EHLO zombo.invalid", "QUIT"]);
    let fs = smtp_findings_at(&r, &[], NOW);
    assert_eq!(codes(&fs), ["smtp_no_starttls"]);
    assert_eq!(fs[0].severity, Severity::Warning);
}

#[tokio::test]
async fn a_refused_starttls_is_reported_with_its_code() {
    let srv = FakeSmtp::start(vec![
        say("220 mail.example.test ESMTP\r\n"),
        Step::Expect("EHLO"),
        say(EHLO_PLAIN),
        Step::Expect("STARTTLS"),
        say("454 TLS not available due to temporary reason\r\n"),
        Step::Expect("QUIT"),
        say("221 bye\r\n"),
    ])
    .await;
    let r = run(srv.addr, &options(Mode::Starttls), &RootCertStore::empty()).await;
    assert!(matches!(&r.starttls, Starttls::Refused { code: 454, .. }), "{:?}", r.starttls);
    let fs = smtp_findings_at(&r, &[], NOW);
    assert_eq!(codes(&fs), ["smtp_starttls_failed"]);
    assert!(fs[0].message.contains("454"), "{}", fs[0].message);
}

#[tokio::test]
async fn a_failed_handshake_after_starttls_is_reported() {
    let srv = FakeSmtp::start(vec![
        say("220 mail.example.test ESMTP\r\n"),
        Step::Expect("EHLO"),
        say(EHLO_PLAIN),
        Step::Expect("STARTTLS"),
        say("220 go ahead\r\n"),
        say("this is not a TLS server\r\n"),
    ])
    .await;
    let r = run(srv.addr, &options(Mode::Starttls), &RootCertStore::empty()).await;
    assert!(matches!(r.starttls, Starttls::HandshakeFailed(_)), "{:?}", r.starttls);
    assert_eq!(codes(&smtp_findings_at(&r, &[], NOW)), ["smtp_starttls_failed"]);
}

#[tokio::test]
async fn implicit_tls_reads_the_greeting_inside_the_tunnel() {
    let ca = Ca::root("Test Root CA");
    let srv = FakeSmtp::start(vec![
        Step::Tls(server(&ca, &[HOST])),
        say("220 mail.example.test ESMTP\r\n"),
        Step::Expect("EHLO"),
        say("250-mail.example.test\r\n250 AUTH PLAIN\r\n"),
        Step::Expect("QUIT"),
        say("221 bye\r\n"),
    ])
    .await;
    let r = run(srv.addr, &options(Mode::Implicit), &ca.roots()).await;
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert_eq!((r.mode, &r.starttls), (Mode::Implicit, &Starttls::NotApplicable));
    assert_eq!(r.banner.as_ref().unwrap().hostname.as_deref(), Some(HOST));
    assert_eq!(r.extensions.as_ref().unwrap().auth, ["PLAIN"]);
    assert_eq!(srv.received(), ["EHLO zombo.invalid", "QUIT"]);
    let fs = smtp_findings_at(&r, &[], NOW);
    assert_eq!(codes(&fs), ["ssl_inspection_valid", "smtp_tls_ok"], "AUTH inside implicit TLS is normal");
}

#[tokio::test]
async fn certificate_problems_use_the_tls_findings() {
    let ca = Ca::root("Test Root CA");
    let srv = FakeSmtp::start(starttls_script(EHLO_PLAIN, server(&ca, &["other.example.test"]))).await;
    let r = run(srv.addr, &options(Mode::Starttls), &ca.roots()).await;
    let fs = smtp_findings_at(&r, &[], NOW);
    assert!(codes(&fs).contains(&"ssl_inspection_hostname_mismatch"), "{:?}", codes(&fs));

    let leaf = ca.leaf(&[HOST], days(-90), days(-1));
    let srv = FakeSmtp::start(starttls_script(EHLO_PLAIN, pki::server_config(vec![leaf.der], leaf.key))).await;
    let r = run(srv.addr, &options(Mode::Starttls), &ca.roots()).await;
    let fs = smtp_findings_at(&r, &[], NOW);
    assert!(codes(&fs).contains(&"ssl_inspection_expired"), "{:?}", codes(&fs));
}

#[tokio::test]
async fn a_greeting_that_is_not_220_stops_the_dialogue() {
    let srv = FakeSmtp::start(vec![say("554 5.7.1 no SMTP service here for you\r\n")]).await;
    let r = run(srv.addr, &options(Mode::Starttls), &RootCertStore::empty()).await;
    assert!(srv.received().is_empty(), "nothing is sent to a server that said no");
    let fs = smtp_findings_at(&r, &[], NOW);
    assert_eq!(codes(&fs), ["smtp_banner_rejected"]);
    assert!(fs[0].message.contains("554"));
}

#[tokio::test]
async fn the_greeting_name_is_compared_with_the_expected_names() {
    let srv = FakeSmtp::start(vec![say("220 smtp.other.test ESMTP\r\n"), Step::Expect("EHLO"), say("250 smtp.other.test\r\n"), Step::Expect("QUIT")]).await;
    let r = run(srv.addr, &options(Mode::Starttls), &RootCertStore::empty()).await;
    let expect = vec![HOST.to_string(), "ptr.example.test.".to_string()];
    let fs = smtp_findings_at(&r, &expect, NOW);
    let f = fs.iter().find(|f| f.code == "smtp_banner_name_mismatch").unwrap();
    assert_eq!(f.severity, Severity::Info);
    assert!(f.message.contains("smtp.other.test") && f.message.contains("mail.example.test, ptr.example.test"), "{}", f.message);

    let same = vec!["SMTP.Other.Test.".to_string()];
    assert!(!codes(&smtp_findings_at(&r, &same, NOW)).contains(&"smtp_banner_name_mismatch"));
    assert!(!codes(&smtp_findings_at(&r, &[], NOW)).contains(&"smtp_banner_name_mismatch"), "no names to compare, no finding");
}

async fn hostile(script: Vec<Step>) -> SmtpResult {
    let srv = FakeSmtp::start(script).await;
    run(srv.addr, &options(Mode::Starttls), &RootCertStore::empty()).await
}

#[tokio::test]
async fn hostile_replies_are_refused_without_panic() {
    let long_line = format!("220 {}\r\n", "A".repeat(600));
    let r = hostile(vec![Step::Raw(long_line.into_bytes())]).await;
    assert_eq!(r.failure.as_ref().unwrap().stage, Stage::Greeting);
    assert!(r.failure.as_ref().unwrap().message.contains("512"), "{:?}", r.failure);

    let no_newline = hostile(vec![Step::Raw(vec![b'2'; 100_000])]).await;
    assert_eq!(no_newline.failure.as_ref().unwrap().stage, Stage::Greeting);

    let many = "220-line\r\n".repeat(100);
    let r = hostile(vec![say(&many)]).await;
    assert!(r.failure.as_ref().unwrap().message.contains("64 lines"), "{:?}", r.failure);

    let r = hostile(vec![say("220-a\r\n250 b\r\n")]).await;
    assert!(r.failure.as_ref().unwrap().message.contains("not an SMTP reply"), "{:?}", r.failure);

    for junk in [&b"\x00\x01\x02\xff\xfe\r\n"[..], b"HTTP/1.1 400 Bad Request\r\n", b"\r\n", b"999 nope\r\n", b"220x\r\n"] {
        let r = hostile(vec![Step::Raw(junk.to_vec())]).await;
        assert!(r.failure.is_some(), "{junk:?}");
        assert_eq!(r.reach, Reach::Answered);
    }
}

#[tokio::test]
async fn control_characters_never_reach_a_finding() {
    let r = hostile(vec![say("220 mail.example.test \x1b[31mESMTP\x07\r\n"), Step::Expect("EHLO"), say("554 \x1b[2Jgo away\r\n"), Step::Close]).await;
    let fs = smtp_findings_at(&r, &[], NOW);
    for f in &fs {
        assert!(!f.message.chars().any(char::is_control), "{:?}", f.message);
    }
    assert!(!r.banner.unwrap().text.chars().any(char::is_control));
}

#[tokio::test]
async fn bytes_sent_after_the_starttls_reply_are_refused() {
    let r = hostile(vec![
        say("220 mail.example.test ESMTP\r\n"),
        Step::Expect("EHLO"),
        say(EHLO_PLAIN),
        Step::Expect("STARTTLS"),
        say("220 go ahead\r\n250 AUTH injected\r\n"),
    ])
    .await;
    assert_eq!(r.failure.as_ref().unwrap().stage, Stage::Starttls);
    assert!(r.tls.is_none());
}

#[tokio::test]
async fn a_silent_server_is_reported_as_no_greeting() {
    let addr = pki::serve_silent().await;
    let mut o = options(Mode::Starttls);
    o.timing.step = Duration::from_millis(300);
    let r = run(addr, &o, &RootCertStore::empty()).await;
    assert_eq!((r.reach, r.failure.as_ref().unwrap().stage), (Reach::Answered, Stage::Greeting));
    assert_eq!(codes(&smtp_findings_at(&r, &[], NOW)), ["smtp_no_greeting"]);
}

#[tokio::test]
async fn a_server_that_never_finishes_a_reply_hits_the_overall_deadline() {
    let srv = FakeSmtp::start(vec![say("220-hello\r\n"), Step::Drip(Duration::from_millis(50))]).await;
    let mut o = options(Mode::Starttls);
    o.timing = Timing { connect: Duration::from_secs(2), step: Duration::from_secs(30), overall: Duration::from_millis(600) };
    let started = Instant::now();
    let r = run(srv.addr, &o, &RootCertStore::empty()).await;
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    assert_eq!(r.failure.as_ref().unwrap().stage, Stage::Overall);
    assert_eq!(r.reach, Reach::Answered);
}

#[tokio::test]
async fn a_closed_port_is_refused_not_silent() {
    let addr = fake::closed_port().await;
    let r = run(addr, &options(Mode::Starttls), &RootCertStore::empty()).await;
    assert_eq!(r.reach, Reach::Refused);
    assert_eq!(codes(&smtp_findings_at(&r, &[], NOW)), ["smtp_refused"]);
}

#[test]
fn silence_on_a_mail_port_says_no_answer_and_names_the_network() {
    let mut r = SmtpResult {
        host: HOST.into(),
        port: 25,
        mode: Mode::Starttls,
        reach: Reach::NoAnswer,
        peer: None,
        banner: None,
        extensions: None,
        starttls: Starttls::NotAttempted,
        tls: None,
        extensions_after_tls: None,
        failure: None,
    };
    let fs = smtp_findings_at(&r, &[], NOW);
    assert_eq!(codes(&fs), ["smtp_no_answer"]);
    assert_eq!(fs[0].severity, Severity::Info);
    assert!(fs[0].message.contains("block outbound mail"), "{}", fs[0].message);
    r.port = 2222;
    assert!(!smtp_findings_at(&r, &[], NOW)[0].message.contains("outbound mail"));
}

#[tokio::test]
async fn an_ehlo_name_that_could_inject_commands_is_refused_before_connecting() {
    let srv = FakeSmtp::start(vec![say("220 mail.example.test ESMTP\r\n"), Step::ExpectAny]).await;
    let mut o = options(Mode::Starttls);
    o.ehlo_name = "a.test\r\nMAIL FROM:<x@y.test>".into();
    let r = run(srv.addr, &o, &RootCertStore::empty()).await;
    assert_eq!(r.failure.as_ref().unwrap().stage, Stage::Setup);
    assert!(r.peer.is_none() && srv.received().is_empty());
}

#[tokio::test]
async fn a_server_that_rejects_ehlo_is_reported() {
    let r = hostile(vec![say("220 mail.example.test ESMTP\r\n"), Step::Expect("EHLO"), say("502 5.5.2 command not recognized\r\n")]).await;
    assert_eq!(r.failure.as_ref().unwrap().stage, Stage::Ehlo);
    assert_eq!(codes(&smtp_findings_at(&r, &[], NOW)), ["smtp_protocol_error"]);
}
