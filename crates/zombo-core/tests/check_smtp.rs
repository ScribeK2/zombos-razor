#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! The SMTP banner Check as the UI runs it. `Request::port` is where the fake mail servers listen.
//! The MX hosts are loopback addresses written as names (`127.0.0.2.`): `check_smtp` dials them
//! without a lookup, 127.0.0.1 answers, and any other address on the same port refuses at once. The
//! machine's resolvers are fake DNS servers, or none.

mod common;
#[path = "common/smtp.rs"]
mod fake;
#[path = "common/smtp_hosts.rs"]
mod hosts;
#[path = "common/tls.rs"]
mod pki;

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use common::FakeDns;
use fake::{FakeSmtp, Step, say};
use hosts::MailHost;
use zombo_core::{
    Severity,
    check::{Fact, Outcome, Request},
    smtp::{CHECK, PORTS},
    target::{Kind, parse_target},
};

const T: Duration = Duration::from_secs(8);
const NO_RESOLVER: &[SocketAddr] = &[];

fn rows(f: &[Fact]) -> Vec<String> {
    f.iter().map(Fact::record).collect()
}

fn found(o: &Outcome) -> Vec<(&'static str, Severity)> {
    o.findings.iter().map(|f| (f.code, f.severity)).collect()
}

fn request<'a>(name: &'a str, kind: Kind, port: u16, machine: &'a [SocketAddr]) -> Request<'a> {
    Request { port, kind, machine_resolvers: Some(machine), ..Request::system(name, T, &[]) }
}

/// Four loopback hosts on one port: 127.0.0.1 answers, 127.0.0.2 to 127.0.0.4 refuse.
async fn mail() -> MailHost {
    MailHost::start("127.0.0.1", 0, "mail.example.test").await
}

fn mx_zone(name: &str, list: &[(u16, &str)]) -> String {
    list.iter().map(|(p, h)| format!("{name}. 300 IN MX {p} {h}.\n")).collect()
}

const SILENT_NOTE: &str = "127.0.0.2, the most preferred MX host: none of the first 3 answered";

#[tokio::test]
async fn a_greeting_on_the_chosen_port_gives_the_server_rows_and_the_findings() {
    let srv = FakeSmtp::start(vec![
        say("220 mail.example.test ESMTP ready\r\n"),
        Step::Expect("EHLO"),
        say("250-mail.example.test\r\n250-SIZE 1000\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n"),
        Step::Expect("QUIT"),
        say("221 bye\r\n"),
    ])
    .await;
    let port = srv.addr.port();
    let o = CHECK.run(&request("127.0.0.1", Kind::Ip, port, NO_RESOLVER)).await.unwrap();
    assert_eq!(
        rows(&o.facts),
        [
            format!("Server: 127.0.0.1:{port} (127.0.0.1)"),
            "Reached: answered".into(),
            "Banner: 220 mail.example.test ESMTP ready".into(),
            "Offers: 8BITMIME, SIZE 1000, AUTH PLAIN".into(),
            "STARTTLS: not offered".into(),
        ]
    );
    assert!(o.details.is_empty());
    assert_eq!(o.details_title, "After STARTTLS");
    assert_eq!(found(&o), [("smtp_no_starttls", Severity::Warning), ("smtp_auth_before_tls", Severity::Warning)]);
    assert_eq!(srv.received(), ["EHLO zombo.invalid", "QUIT"], "no mail is sent");
}

#[tokio::test]
async fn a_server_that_upgrades_gives_the_tls_rows_and_the_after_starttls_details() {
    let ca = pki::Ca::root("Test Root CA");
    let now = time::OffsetDateTime::now_utc();
    let leaf = ca.leaf(&["mail.example.test"], now - time::Duration::days(1), now + time::Duration::days(60));
    let srv = FakeSmtp::start(vec![
        say("220 mail.example.test ESMTP ready\r\n"),
        Step::Expect("EHLO"),
        say("250-mail.example.test\r\n250 STARTTLS\r\n"),
        Step::Expect("STARTTLS"),
        say("220 Ready\r\n"),
        Step::Tls(pki::server_config(vec![leaf.der], leaf.key)),
        Step::Expect("EHLO"),
        say("250-mail.example.test\r\n250-AUTH PLAIN LOGIN\r\n250 PIPELINING\r\n"),
        Step::Expect("QUIT"),
        say("221 bye\r\n"),
    ])
    .await;
    let o = CHECK.run(&request("127.0.0.1", Kind::Ip, srv.addr.port(), NO_RESOLVER)).await.unwrap();
    let keys: Vec<_> = o.facts.iter().map(|f| f.key.as_str()).collect();
    assert_eq!(
        keys,
        ["Server", "Reached", "Banner", "Offers", "STARTTLS", "Protocol", "Cipher", "Trust", "Certificate"]
    );
    let r = rows(&o.facts);
    assert_eq!(r[4], "STARTTLS: upgraded to TLS");
    assert!(r[8].starts_with("Certificate: mail.example.test, expires "), "{}", r[8]);
    assert_eq!(rows(&o.details), ["Offers after STARTTLS: PIPELINING, AUTH PLAIN LOGIN"]);
    assert_eq!(o.findings.last().map(|f| (f.code, f.severity)), Some(("smtp_tls_ok", Severity::Ok)));
}

#[tokio::test]
async fn a_refused_starttls_and_a_refused_connection_say_so() {
    let srv = FakeSmtp::start(vec![
        say("220 mail.example.test ESMTP ready\r\n"),
        Step::Expect("EHLO"),
        say("250-mail.example.test\r\n250 STARTTLS\r\n"),
        Step::Expect("STARTTLS"),
        say("454 TLS not available\r\n"),
        Step::Expect("QUIT"),
        say("221 bye\r\n"),
    ])
    .await;
    let o = CHECK.run(&request("127.0.0.1", Kind::Ip, srv.addr.port(), NO_RESOLVER)).await.unwrap();
    assert_eq!(rows(&o.facts)[4], "STARTTLS: refused: 454 TLS not available");
    assert_eq!(found(&o), [("smtp_starttls_failed", Severity::Warning)]);

    let closed = fake::closed_port().await.port();
    let o = CHECK.run(&request("127.0.0.1", Kind::Ip, closed, NO_RESOLVER)).await.unwrap();
    assert_eq!(rows(&o.facts)[..2], [format!("Server: 127.0.0.1:{closed}"), "Reached: refused".into()]);
    assert_eq!(found(&o), [("smtp_refused", Severity::Warning)]);
}

/// The name as a domain, and as the rep's other three kinds of target, with an MX record that points
/// at 127.0.0.3 and a typed host at 127.0.0.1: the kind alone picks the path.
#[tokio::test]
async fn the_kind_of_target_decides_between_the_mx_hosts_and_the_name_as_typed() {
    let typed = mail().await;
    let port = typed.addr.port();
    let via_mx = MailHost::start("127.0.0.3", port, "mx.example.test").await;
    let dns = FakeDns::start(&mx_zone("127.0.0.1", &[(10, "127.0.0.3")])).await;
    let machine = [dns.addr];
    for (kind, goes_through_mx) in
        [(Kind::Domain, true), (Kind::Email, true), (Kind::Hostname, false), (Kind::Ip, false)]
    {
        let o = CHECK.run(&request("127.0.0.1", kind, port, &machine)).await.unwrap();
        let r = rows(&o.facts);
        let (host, via) = if goes_through_mx {
            ("127.0.0.3", "Dialled: 127.0.0.3, the most preferred MX host")
        } else {
            ("127.0.0.1", "")
        };
        assert_eq!(r.iter().any(|l| l == via), goes_through_mx, "{kind:?}: {r:?}");
        assert!(r.contains(&format!("Server: {host}:{port} ({host})")), "{kind:?}: {r:?}");
        assert_eq!(r.iter().any(|l| l.starts_with("MX: ")), goes_through_mx, "{kind:?}");
    }
    assert_eq!((typed.connections(), via_mx.connections()), (2, 2));
}

/// The email `bob@mail.example.test` runs with the name `mail.example.test`, which parsed on its
/// own is a host name. Deriving the path from the name would dial it as typed, so the request
/// carries the kind.
#[tokio::test]
async fn an_email_whose_domain_is_a_host_name_still_goes_through_its_mx_hosts() {
    assert_eq!(parse_target("mail.example.test").unwrap().kind, Kind::Hostname);
    assert_eq!(parse_target("bob@mail.example.test").unwrap().kind, Kind::Email);
    let srv = mail().await;
    let dns = FakeDns::start(&mx_zone("mail.example.test", &[(10, "127.0.0.1")])).await;
    let machine = [dns.addr];
    let o = CHECK.run(&request("mail.example.test", Kind::Email, srv.addr.port(), &machine)).await.unwrap();
    let r = rows(&o.facts);
    assert_eq!(r[0], "MX: 10 127.0.0.1");
    assert_eq!(r[1], "Dialled: 127.0.0.1, the most preferred MX host");
    assert_eq!(srv.connections(), 1);
}

#[tokio::test]
async fn mx_hosts_are_tried_in_preference_order_and_the_first_that_answers_ends_the_search() {
    let srv = mail().await;
    let port = srv.addr.port();
    let later = MailHost::start("127.0.0.3", port, "later.example.test").await;
    let zone = mx_zone("example.test", &[(30, "127.0.0.3"), (20, "127.0.0.1"), (10, "127.0.0.2")]);
    let dns = FakeDns::start(&zone).await;
    let machine = [dns.addr];
    let o = CHECK.run(&request("example.test", Kind::Domain, port, &machine)).await.unwrap();
    assert_eq!(
        rows(&o.facts)[..5],
        [
            "MX: 10 127.0.0.2",
            "MX: 20 127.0.0.1",
            "MX: 30 127.0.0.3",
            "Dialled: 127.0.0.1, the most preferred MX host that answered",
            format!("Server: 127.0.0.1:{port} (127.0.0.1)").as_str(),
        ]
    );
    assert_eq!((srv.connections(), later.connections()), (1, 0), "the third host was never dialled");
}

#[tokio::test]
async fn only_the_first_three_mx_hosts_are_tried_and_the_report_is_about_the_most_preferred() {
    let srv = mail().await;
    let zone = mx_zone("example.test", &[(10, "127.0.0.2"), (20, "127.0.0.3"), (30, "127.0.0.4"), (40, "127.0.0.1")]);
    let dns = FakeDns::start(&zone).await;
    let machine = [dns.addr];
    let port = srv.addr.port();
    let o = CHECK.run(&request("example.test", Kind::Domain, port, &machine)).await.unwrap();
    let r = rows(&o.facts);
    assert_eq!(r[..4], ["MX: 10 127.0.0.2", "MX: 20 127.0.0.3", "MX: 30 127.0.0.4", "MX: 40 127.0.0.1"]);
    assert_eq!(r[4], format!("Dialled: {SILENT_NOTE}"));
    assert_eq!(r[5], format!("Server: 127.0.0.2:{port}"));
    assert_eq!(found(&o), [("smtp_refused", Severity::Warning)]);
    assert_eq!(srv.connections(), 0, "the fourth host is past the limit");
}

#[tokio::test]
async fn a_domain_with_no_mx_is_dialled_by_its_own_name() {
    let srv = mail().await;
    let dns = FakeDns::start("127.0.0.1. 300 IN A 192.0.2.1\n").await;
    let machine = [dns.addr];
    let o = CHECK.run(&request("127.0.0.1", Kind::Domain, srv.addr.port(), &machine)).await.unwrap();
    assert_eq!(rows(&o.facts)[0], "Dialled: 127.0.0.1, the name itself: the domain has no MX record");
    assert_eq!(srv.connections(), 1);
}

/// The machine has no resolver here, so the silent bootstrap resolver is the one asked, and the run
/// has no PTR step to add to the time: what is measured is the MX lookup alone.
#[tokio::test]
async fn an_mx_lookup_nobody_answers_gives_up_after_five_seconds_and_dials_the_name_itself() {
    let srv = mail().await;
    let silent = FakeDns::silent().await;
    let bootstrap = [silent.addr];
    let r = Request {
        port: srv.addr.port(),
        kind: Kind::Domain,
        machine_resolvers: Some(NO_RESOLVER),
        query: Duration::from_millis(50),
        ..Request::system("127.0.0.1", T, &bootstrap)
    };
    let started = Instant::now();
    let o = CHECK.run(&r).await.unwrap();
    let took = started.elapsed();
    let first = &rows(&o.facts)[0];
    assert!(first.starts_with("Dialled: 127.0.0.1, the name itself: the MX lookup failed ("), "{first}");
    assert!(took >= Duration::from_millis(4500), "the MX lookup gave up after {took:?}, not 5 s");
    assert!(took < Duration::from_secs(7), "{took:?}");
    assert_eq!(srv.connections(), 1);
}

#[tokio::test]
async fn a_machine_with_no_resolver_asks_the_bootstrap_resolvers_for_the_mx_hosts() {
    let srv = mail().await;
    let dns = FakeDns::start(&mx_zone("example.test", &[(10, "127.0.0.1")])).await;
    let bootstrap = [dns.addr];
    let r = Request {
        port: srv.addr.port(),
        kind: Kind::Domain,
        machine_resolvers: Some(NO_RESOLVER),
        ..Request::system("example.test", T, &bootstrap)
    };
    let o = CHECK.run(&r).await.unwrap();
    assert_eq!(rows(&o.facts)[..2], ["MX: 10 127.0.0.1", "Dialled: 127.0.0.1, the most preferred MX host"]);

    // With a machine resolver, the bootstrap ones are not asked for the MX hosts.
    let elsewhere = FakeDns::start(&mx_zone("example.test", &[(10, "127.0.0.2")])).await;
    let bootstrap = [elsewhere.addr];
    let machine = [dns.addr];
    let r = Request {
        port: srv.addr.port(),
        kind: Kind::Domain,
        machine_resolvers: Some(&machine),
        ..Request::system("example.test", T, &bootstrap)
    };
    let o = CHECK.run(&r).await.unwrap();
    assert_eq!(rows(&o.facts)[0], "MX: 10 127.0.0.1");
}

const PTR: &str = "1.0.0.127.in-addr.arpa. 300 IN PTR mail.example.test.\nmail.example.test. 300 IN A 127.0.0.1\n";

#[tokio::test]
async fn the_greeting_is_compared_with_the_ptr_names_of_the_address_that_answered() {
    let srv = MailHost::start("127.0.0.1", 0, "other.example.test").await;
    let dns = FakeDns::start(PTR).await;
    let machine = [dns.addr];
    let o = CHECK.run(&request("127.0.0.1", Kind::Ip, srv.addr.port(), &machine)).await.unwrap();
    let mismatch = o.findings.iter().find(|f| f.code == "smtp_banner_name_mismatch").expect("no mismatch finding");
    assert_eq!(mismatch.title, "The greeting names other.example.test");
    assert!(mismatch.message.contains("none of mail.example.test"), "{}", mismatch.message);

    let agreeing = MailHost::start("127.0.0.1", 0, "mail.example.test").await;
    let o = CHECK.run(&request("127.0.0.1", Kind::Ip, agreeing.addr.port(), &machine)).await.unwrap();
    assert!(o.findings.iter().all(|f| f.code != "smtp_banner_name_mismatch"), "{:?}", found(&o));
}

#[tokio::test]
async fn a_machine_with_no_resolver_skips_the_ptr_step_even_when_the_bootstrap_resolvers_know_one() {
    let srv = MailHost::start("127.0.0.1", 0, "other.example.test").await;
    let dns = FakeDns::start(PTR).await;
    let bootstrap = [dns.addr];
    let r = Request {
        port: srv.addr.port(),
        kind: Kind::Ip,
        machine_resolvers: Some(NO_RESOLVER),
        ..Request::system("127.0.0.1", T, &bootstrap)
    };
    let o = CHECK.run(&r).await.unwrap();
    assert!(o.findings.iter().all(|f| f.code != "smtp_banner_name_mismatch"), "{:?}", found(&o));
}

#[tokio::test]
async fn a_host_name_that_was_dialled_is_one_of_the_names_the_greeting_may_have() {
    let srv = MailHost::start("127.0.0.1", 0, "other.example.test").await;
    let o = CHECK.run(&request("localhost", Kind::Hostname, srv.addr.port(), NO_RESOLVER)).await.unwrap();
    let mismatch = o.findings.iter().find(|f| f.code == "smtp_banner_name_mismatch").expect("no mismatch finding");
    assert!(mismatch.message.contains("none of localhost"), "{}", mismatch.message);
}

#[tokio::test]
async fn the_ptr_question_has_three_seconds_and_the_request_query_is_not_used() {
    let srv = mail().await;
    let silent = FakeDns::silent().await;
    let machine = [silent.addr];
    let started = Instant::now();
    let r = Request { query: Duration::from_millis(50), ..request("127.0.0.1", Kind::Ip, srv.addr.port(), &machine) };
    let o = CHECK.run(&r).await.unwrap();
    let took = started.elapsed();
    assert_eq!(rows(&o.facts)[1], "Reached: answered");
    assert!(took >= Duration::from_millis(2800), "the PTR question gave up after {took:?}, not 3 s");
    assert!(took < Duration::from_secs(5), "{took:?}");
}

/// Nobody sets the kind in a plain `Request::system`, so an address must not go through MX.
#[tokio::test]
async fn a_system_request_takes_its_kind_from_its_name() {
    for (name, kind) in [
        ("127.0.0.1", Kind::Ip),
        ("example.com", Kind::Domain),
        ("www.example.com", Kind::Hostname),
        ("bob@example.com", Kind::Email),
        ("not a name", Kind::Hostname),
    ] {
        assert_eq!(Request::system(name, T, &[]).kind, kind, "{name}");
    }
    let srv = mail().await;
    let r =
        Request { port: srv.addr.port(), machine_resolvers: Some(NO_RESOLVER), ..Request::system("127.0.0.1", T, &[]) };
    let o = CHECK.run(&r).await.unwrap();
    assert_eq!(rows(&o.facts)[0], format!("Server: 127.0.0.1:{} (127.0.0.1)", srv.addr.port()));
}

#[test]
fn the_descriptor_names_the_row_its_brief_its_limits_and_what_it_owns() {
    assert_eq!(CHECK.label, "SMTP banner");
    assert!(CHECK.is_on_demand() && CHECK.automatic_for.is_empty());
    let brief = CHECK.on_demand.unwrap();
    assert_eq!(brief.run_label, "Run SMTP banner check");
    assert!(brief.what.starts_with("Connects to the target's mail port"));
    assert!(brief.contacts.contains("(up to 3 are tried)"));
    assert!(brief.note.unwrap().starts_with("Port 25 is often blocked outbound"));
    assert!(CHECK.takes_chosen_port, "the rep's port choice must reach the Check");
    assert_eq!(CHECK.budget, (Duration::from_secs(40), Duration::from_secs(40)));
    assert_eq!(CHECK.owns, ["smtp_"]);
    assert_eq!(CHECK.blind_spots.len(), 4);
    assert_eq!(CHECK.blind_spots[2], "MX hosts after the first three tried.");
    assert_eq!(PORTS, [25, 587, 465]);
}

/// Dials a real mail host on port 25, which many networks block. Run on a network that does not
/// intercept DNS: `cargo test -p zombo-core --test check_smtp -- --ignored`.
#[tokio::test]
#[ignore = "needs a real network"]
async fn live_a_real_mail_host_gives_a_server_row_and_a_reach_row() {
    let r = Request { port: 25, ..Request::system("gmail-smtp-in.l.google.com", Duration::from_secs(10), &[]) };
    let o = CHECK.run(&r).await.unwrap();
    assert_eq!(o.facts[0].key, "Server");
    let reached = &o.facts[1];
    assert_eq!(reached.key, "Reached");
    let allowed = ["answered", "no answer", "refused", "no route from this network", "failed"];
    assert!(allowed.contains(&reached.value.as_str()), "{}", reached.value);
}
