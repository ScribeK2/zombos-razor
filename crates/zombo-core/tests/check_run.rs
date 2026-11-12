#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! `run_by_id` as the CLI calls it: the same Outcome as the descriptor, and every way a run can fail.
mod common;
#[path = "common/tls.rs"]
mod pki;

use std::time::{Duration, Instant, UNIX_EPOCH};

use common::{FakeDns, dnssec_zone};
use pki::Ca;
use zombo_core::{
    Finding, Severity,
    check::{ALL, Fact, Outcome, Report, Request, RunArgs, RunError, Seams, run_by_id},
    dnssec,
    propagation::Vantage,
    target::{Kind, parse_target},
};

const T: Duration = Duration::from_millis(500);
const APEX: &str = "cloudflare.com";
const SIGNED_AT: u64 = 1794141381 + 3600;
const CONFIRMED: &str =
    "7.113.0.203.in-addr.arpa. 300 IN PTR mail.example.com.\nmail.example.com. 300 IN A 203.0.113.7\n";

fn rows(o: &Outcome) -> Vec<String> {
    o.facts.iter().map(Fact::record).collect()
}

/// A fake recursive resolver that knows the zone's NS, its DS and an A record, and validates; and an
/// authoritative nameserver serving the zone.
async fn zone_fakes() -> (FakeDns, FakeDns) {
    let z = dnssec_zone(APEX);
    let ns = FakeDns::start(&z).await.authoritative();
    let rec = FakeDns::start(&format!(
        "{APEX}. 300 IN NS ns1.{APEX}.\nns1.{APEX}. 300 IN A 127.0.0.1\n{APEX}. 300 IN A 192.0.2.1\n{z}"
    ))
    .await
    .validating();
    (ns, rec)
}

#[tokio::test]
async fn run_by_id_gives_the_outcome_the_descriptor_gives() {
    let (ns, rec) = zone_fakes().await;
    let validating = [Vantage::resolver("Fake", "Test", rec.addr)];
    let seams = Seams {
        ns_port: ns.addr.port(),
        now: UNIX_EPOCH + Duration::from_secs(SIGNED_AT),
        validating: Some(&validating),
        ..Seams::default()
    };
    let name = format!("www.{APEX}");
    let direct = dnssec::CHECK.run(&Request { seams, ..Request::system(&name, T, &[rec.addr]) }).await.unwrap();
    let args = RunArgs { timeout: Some(T), resolvers: &[rec.addr], seams, ..RunArgs::new(&name) };
    let report = run_by_id("dnssec", &args).await.unwrap();
    assert_eq!((report.id, report.label, report.subject.as_str()), ("dnssec", "DNSSEC", name.as_str()));
    assert_eq!(serde_json::to_value(&report.outcome).unwrap(), serde_json::to_value(&direct).unwrap());
    assert_eq!(report.outcome.findings[0].code, "dnssec_secure");
}

#[tokio::test]
async fn an_email_runs_on_its_domain_part() {
    let (ns, rec) = zone_fakes().await;
    let validating = [Vantage::resolver("Fake", "Test", rec.addr)];
    let seams = Seams {
        ns_port: ns.addr.port(),
        now: UNIX_EPOCH + Duration::from_secs(SIGNED_AT),
        validating: Some(&validating),
        ..Seams::default()
    };
    let args = RunArgs { timeout: Some(T), resolvers: &[rec.addr], seams, ..RunArgs::new("Bob@Cloudflare.com") };
    let report = run_by_id("dnssec", &args).await.unwrap();
    assert_eq!(report.subject, APEX);
    assert_eq!(rows(&report.outcome)[0], "Zone: cloudflare.com");
}

#[tokio::test]
async fn an_unknown_id_lists_the_known_ones() {
    let e = run_by_id("nope", &RunArgs::new("example.com")).await.unwrap_err();
    assert_eq!(e, RunError::UnknownId("nope".into()));
    let text = e.to_string();
    assert!(text.contains("\"nope\""), "{text}");
    for c in ALL {
        assert!(text.contains(c.id), "{text}");
    }
}

#[tokio::test]
async fn a_target_that_does_not_parse_is_bad_target_with_the_parsers_text() {
    let e = run_by_id("dnssec", &RunArgs::new("  ")).await.unwrap_err();
    assert_eq!(e, RunError::BadTarget(parse_target("  ").unwrap_err()));
    assert_eq!(e.to_string(), "enter a domain, host, IP or email address");
}

#[tokio::test]
async fn a_kind_the_check_does_not_accept_is_refused_before_any_query() {
    let e = run_by_id("dnssec", &RunArgs::new("192.0.2.1")).await.unwrap_err();
    assert_eq!(e, RunError::NotAccepted { check: "dnssec", kind: Kind::Ip });
    assert_eq!(e.to_string(), "dnssec does not run on an IP address");
}

#[tokio::test]
async fn a_port_for_a_check_that_takes_none_is_bad_option_naming_the_check() {
    let args = RunArgs { port: Some(25), ..RunArgs::new("example.com") };
    let e = run_by_id("dnssec", &args).await.unwrap_err();
    assert_eq!(e, RunError::BadOption("dnssec does not take a port".into()));
}

#[tokio::test]
async fn a_check_error_is_failed_with_the_checks_own_text() {
    let none: [std::net::SocketAddr; 0] = [];
    let args =
        RunArgs { seams: Seams { machine_resolvers: Some(&none), ..Seams::default() }, ..RunArgs::new("203.0.113.7") };
    let e = run_by_id("rdns", &args).await.unwrap_err();
    assert_eq!(e, RunError::Failed("this machine has no DNS resolver configured".into()));
}

#[tokio::test]
async fn the_chosen_port_reaches_a_check_that_dials_it() {
    let now = time::OffsetDateTime::now_utc();
    let ca = Ca::root("Let's Encrypt R3");
    let leaf = ca.leaf(&["localhost"], now - time::Duration::days(365), now + time::Duration::days(365));
    let port = pki::serve(vec![leaf.der], leaf.key).await.port();
    let args = RunArgs { port: Some(port), timeout: Some(Duration::from_secs(5)), ..RunArgs::new("127.0.0.1") };
    let report = run_by_id("tls-port", &args).await.unwrap();
    assert_eq!(rows(&report.outcome)[0], format!("Port: {port}"));
}

#[tokio::test]
async fn resolvers_replace_the_validating_list_when_no_seam_sets_it() {
    let (ns, rec) = zone_fakes().await;
    let seams = Seams { ns_port: ns.addr.port(), now: UNIX_EPOCH + Duration::from_secs(SIGNED_AT), ..Seams::default() };
    let args = RunArgs { timeout: Some(T), resolvers: &[rec.addr], seams, ..RunArgs::new(APEX) };
    let report = run_by_id("dnssec", &args).await.unwrap();
    // The fake is the only validating resolver asked, and it is named by its address.
    assert_eq!(
        rows(&report.outcome)[..2],
        ["Zone: cloudflare.com".to_string(), format!("Resolver {}: SECURE", rec.addr)]
    );
    assert_eq!(rows(&report.outcome).iter().filter(|r| r.starts_with("Resolver ")).count(), 1);
}

#[tokio::test]
async fn the_validating_seam_wins_over_resolvers() {
    let (ns, rec) = zone_fakes().await;
    let validating = [Vantage::resolver("Seam", "Test", rec.addr)];
    let seams = Seams {
        ns_port: ns.addr.port(),
        now: UNIX_EPOCH + Duration::from_secs(SIGNED_AT),
        validating: Some(&validating),
        ..Seams::default()
    };
    let args = RunArgs { timeout: Some(T), resolvers: &[rec.addr], seams, ..RunArgs::new(APEX) };
    let report = run_by_id("dnssec", &args).await.unwrap();
    assert!(rows(&report.outcome).contains(&"Resolver Seam: SECURE".to_string()), "{:?}", rows(&report.outcome));
}

#[tokio::test]
async fn resolvers_stand_in_for_this_machines_resolvers() {
    let dns = FakeDns::start(CONFIRMED).await;
    let args = RunArgs { timeout: Some(T), resolvers: &[dns.addr], ..RunArgs::new("203.0.113.7") };
    let report = run_by_id("rdns", &args).await.unwrap();
    assert_eq!(report.outcome.findings[0].code, "rdns_confirmed");
}

#[tokio::test]
async fn the_machine_seam_wins_over_resolvers() {
    let good = FakeDns::start(CONFIRMED).await;
    let empty = FakeDns::start("").await;
    let machine = [empty.addr];
    let args = RunArgs {
        timeout: Some(T),
        resolvers: &[good.addr],
        seams: Seams { machine_resolvers: Some(&machine), ..Seams::default() },
        ..RunArgs::new("203.0.113.7")
    };
    let report = run_by_id("rdns", &args).await.unwrap();
    assert_eq!(report.outcome.findings[0].code, "rdns_no_ptr");
}

#[tokio::test]
async fn a_tiny_timeout_ends_a_run_against_a_silent_server_at_once() {
    let silent = FakeDns::silent().await;
    let args =
        RunArgs { timeout: Some(Duration::from_millis(50)), resolvers: &[silent.addr], ..RunArgs::new("example.com") };
    let started = Instant::now();
    let result = run_by_id("dnssec", &args).await;
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    assert!(
        !matches!(result, Err(RunError::UnknownId(_) | RunError::BadTarget(_) | RunError::BadOption(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn an_outcome_serialises_to_four_keys_and_lowercase_severities() {
    let dns = FakeDns::start(CONFIRMED).await;
    let args = RunArgs { timeout: Some(T), resolvers: &[dns.addr], ..RunArgs::new("203.0.113.7") };
    let report = run_by_id("rdns", &args).await.unwrap();
    let v = serde_json::to_value(&report.outcome).unwrap();
    let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["details", "details_title", "facts", "findings"]);
    assert_eq!(v["findings"][0]["severity"], "ok");
    let mut fact_keys: Vec<_> = v["facts"][0].as_object().unwrap().keys().cloned().collect();
    fact_keys.sort();
    assert_eq!(fact_keys, ["key", "value"]);
}

fn finding(severity: Severity, title: &'static str, recommendation: Option<&'static str>) -> Finding {
    Finding {
        code: "x_test",
        severity,
        title: title.into(),
        message: "A message.".into(),
        recommendation: recommendation.map(Into::into),
    }
}

#[test]
fn the_text_is_a_heading_facts_details_and_findings_in_the_clis_format() {
    let report = Report {
        id: "dnssec",
        label: "DNSSEC",
        subject: "example.com".into(),
        outcome: Outcome {
            findings: vec![
                finding(Severity::Critical, "Broken", Some("Fix it.")),
                finding(Severity::Warning, "Weak", None),
                finding(Severity::Info, "Note", None),
                finding(Severity::Ok, "Fine", None),
            ],
            facts: vec![Fact::new("Zone", "example.com"), Fact::new("Resolver A", "SECURE")],
            details_title: "Keys",
            details: vec![Fact::new("Key", "34505")],
        },
    };
    let want = "\
DNSSEC for example.com

Zone: example.com
Resolver A: SECURE

Keys
  Key: 34505

[CRITICAL] Broken: A message.
        Fix it.
[WARNING] Weak: A message.
[info] Note: A message.
[ok] Fine: A message.";
    assert_eq!(report.to_text(), want);
    assert!(report.to_text().ends_with(&report.outcome.to_text()));
    let bare = Outcome { findings: vec![finding(Severity::Ok, "Fine", None)], ..Outcome::default() };
    assert_eq!(bare.to_text(), "[ok] Fine: A message.");
}
