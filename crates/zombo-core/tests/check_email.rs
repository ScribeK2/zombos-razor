#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! The Email Check as the UI runs it: the first bootstrap resolver is a fake DNS server.
mod common;

use std::{net::SocketAddr, time::Duration};

use common::{FakeDns, zone};
use zombo_core::{
    Severity,
    check::{Fact, Outcome, Request},
    email_auth::{CHECK, DKIM_COMMON_SELECTORS},
    target::Kind,
};

const T: Duration = Duration::from_millis(500);

fn rows(f: &[Fact]) -> Vec<String> {
    f.iter().map(Fact::record).collect()
}

fn found(o: &Outcome) -> Vec<(&'static str, Severity)> {
    o.findings.iter().map(|f| (f.code, f.severity)).collect()
}

async fn run(zone_text: &str, selectors: &[String]) -> Result<Outcome, String> {
    let dns = FakeDns::start(zone_text).await;
    CHECK.run(&Request { selectors, ..Request::system("example.com", T, &[dns.addr]) }).await
}

#[tokio::test]
async fn a_healthy_domain_gives_spf_dmarc_and_dkim_rows_and_ok_findings() {
    let o = run(&zone("email_healthy"), &[]).await.unwrap();
    assert_eq!(
        rows(&o.facts),
        [
            "SPF: v=spf1 include:_spf.provider.test ip4:192.0.2.0/24 ip6:2001:db8::/32 -all",
            "SPF lookups: 1 of 10",
            "DMARC: v=DMARC1; p=reject; sp=quarantine; adkim=s; rua=mailto:dmarc@example.com",
        ]
    );
    assert_eq!(o.details_title, "DKIM keys");
    assert_eq!(
        rows(&o.details),
        ["DKIM selector1: rsa 2048 bits".to_string(), format!("DKIM selectors tried: {}", DKIM_COMMON_SELECTORS.len()),]
    );
    assert_eq!(
        found(&o),
        [
            ("spf_fail_all", Severity::Ok),
            ("dkim_found", Severity::Ok),
            ("dmarc_enforced", Severity::Ok),
            ("email_tlsrpt_missing", Severity::Info),
            ("email_bimi_missing", Severity::Info),
            ("email_mtasts_missing", Severity::Info),
        ]
    );
}

#[tokio::test]
async fn a_custom_selector_in_the_request_is_tried_and_found_and_without_it_is_not() {
    let z = zone("email_dkim_custom");
    let without = run(&z, &[]).await.unwrap();
    assert_eq!(rows(&without.details), [format!("DKIM selectors tried: {}", DKIM_COMMON_SELECTORS.len())]);
    assert!(!found(&without).contains(&("dkim_found", Severity::Ok)), "{:?}", found(&without));

    let selectors = ["acme2024".to_string()];
    let with = run(&z, &selectors).await.unwrap();
    assert_eq!(
        rows(&with.details),
        [
            "DKIM acme2024: rsa 2048 bits".to_string(),
            format!("DKIM selectors tried: {}", DKIM_COMMON_SELECTORS.len() + 1),
        ]
    );
    assert!(found(&with).contains(&("dkim_found", Severity::Ok)), "{:?}", found(&with));
}

#[tokio::test]
async fn no_resolver_in_the_request_gives_the_error_text() {
    let err = CHECK.run(&Request::system("example.com", T, &[])).await;
    assert_eq!(err.unwrap_err(), "no resolver is configured");
}

#[tokio::test]
async fn only_the_first_resolver_is_asked() {
    let dns = FakeDns::start(&zone("email_healthy")).await;
    let silent = FakeDns::silent().await;
    let o = CHECK.run(&Request::system("example.com", T, &[dns.addr, silent.addr])).await.unwrap();
    assert!(o.facts.iter().any(|f| f.key == "SPF"));
    let dead = [silent.addr, dns.addr];
    let err = CHECK.run(&Request::system("example.com", Duration::from_millis(100), &dead)).await;
    assert_eq!(err.unwrap_err(), format!("no answer from DNS resolver {}", silent.addr));
}

#[tokio::test]
async fn a_resolver_that_never_answers_gives_the_no_answer_text() {
    let dns = FakeDns::silent().await;
    let err = CHECK.run(&Request::system("example.com", Duration::from_millis(100), &[dns.addr])).await;
    assert_eq!(err.unwrap_err(), format!("no answer from DNS resolver {}", dns.addr));
}

#[tokio::test]
async fn the_request_query_limits_each_question() {
    let started = std::time::Instant::now();
    let dns = FakeDns::silent().await;
    let _ = CHECK.run(&Request::system("example.com", Duration::from_millis(100), &[dns.addr])).await;
    assert!(started.elapsed() < Duration::from_secs(2), "the request's query timeout was not used");
}

#[test]
fn the_descriptor_names_the_row_the_kinds_it_runs_on_by_itself_and_what_it_owns() {
    assert_eq!(CHECK.label, "Email");
    assert_eq!(CHECK.automatic_for, [Kind::Domain, Kind::Email]);
    assert!(!CHECK.is_on_demand() && CHECK.on_demand.is_none() && !CHECK.takes_chosen_port);
    assert_eq!(CHECK.budget, (Duration::from_secs(25), Duration::from_secs(4)));
    assert_eq!(CHECK.owns, ["spf_", "dkim_", "dmarc_", "email_"]);
    assert_eq!(CHECK.blind_spots.len(), 4);
}

/// Reads the real resolvers. Run on a network that does not intercept DNS:
/// `cargo test -p zombo-core --test check_email -- --ignored`.
#[tokio::test]
#[ignore = "needs a real network"]
async fn live_a_real_domain_gives_an_spf_row_or_the_no_answer_text() {
    let resolver: SocketAddr = "8.8.8.8:53".parse().unwrap();
    match CHECK.run(&Request::system("google.com", Duration::from_secs(4), &[resolver])).await {
        Ok(o) => assert!(!o.facts.is_empty() && o.details_title == "DKIM keys"),
        Err(e) => assert_eq!(e, format!("no answer from DNS resolver {resolver}")),
    }
}
