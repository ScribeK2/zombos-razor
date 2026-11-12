#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! The Delegation Check as the UI runs it: the bootstrap resolver and the nameservers are fake DNS
//! servers. `ns_port` is the port of the parent's server and of the zone's, so one fake plays both.
mod common;

use std::{net::SocketAddr, time::Duration};

use common::FakeDns;
use zombo_core::{
    Severity,
    check::{Fact, Outcome, Request, Seams},
    delegation::CHECK,
    target::Kind,
};

const T: Duration = Duration::from_millis(500);
const BOOTSTRAP: &str = "com. 300 IN NS a.gtld.test.\na.gtld.test. 300 IN A 127.0.0.1\nexample.com. 300 IN NS ns1.example.com.\nexample.com. 300 IN NS ns2.example.com.\nns1.example.com. 300 IN A 127.0.0.1\nns2.example.com. 300 IN A 127.0.0.1\n";
const ZONE: &str = "example.com. 300 IN SOA ns1.example.com. h.example.com. 7 7200 3600 1209600 3600\nexample.com. 300 IN NS ns1.example.com.\nexample.com. 300 IN NS ns2.example.com.\nns1.example.com. 300 IN A 127.0.0.1\nns2.example.com. 300 IN A 127.0.0.1\n";

fn rows(o: &Outcome) -> Vec<String> {
    o.facts.iter().map(Fact::record).collect()
}

fn found(o: &Outcome) -> Vec<(&'static str, Severity)> {
    o.findings.iter().map(|f| (f.code, f.severity)).collect()
}

/// Run against a bootstrap that knows the zone and one server on `port` that is both the parent
/// (a referral) and the zone's nameserver.
async fn run_on(port: u16, name: &str) -> Result<Outcome, String> {
    let rec = FakeDns::start(BOOTSTRAP).await;
    CHECK
        .run(&Request { seams: Seams { ns_port: port, ..Seams::default() }, ..Request::system(name, T, &[rec.addr]) })
        .await
}

#[tokio::test]
async fn a_healthy_delegation_gives_zone_parent_glue_and_server_rows() {
    let server = FakeDns::start(ZONE).await.referral().authoritative();
    let o = run_on(server.addr.port(), "example.com").await.unwrap();
    assert_eq!(
        rows(&o),
        [
            "Zone: example.com",
            "Parent zone: com",
            "Delegated nameserver: ns1.example.com",
            "Delegated nameserver: ns2.example.com",
            "Glue ns1.example.com: 127.0.0.1",
            "Glue ns2.example.com: 127.0.0.1",
            "Server ns1.example.com: answers, SOA serial 7",
            "Server ns2.example.com: answers, SOA serial 7",
        ]
    );
    assert_eq!(found(&o), [("dns_delegation_ok", Severity::Ok)]);
    assert!(o.details.is_empty());
}

#[tokio::test]
async fn a_name_below_the_zone_apex_is_walked_up_to_its_zone() {
    let server = FakeDns::start(ZONE).await.referral().authoritative();
    let o = run_on(server.addr.port(), "www.example.com").await.unwrap();
    assert_eq!(rows(&o)[0], "Zone: example.com", "the zone is found by walking up from the name");
}

#[tokio::test]
async fn a_server_that_answers_without_the_authoritative_flag_is_one_critical_lame_finding() {
    let server = FakeDns::start(ZONE).await.referral().recursion_available(false);
    let o = run_on(server.addr.port(), "example.com").await.unwrap();
    assert_eq!(found(&o), [("dns_delegation_lame", Severity::Critical)]);
    let lame = "lame: No Error (authoritative flag not set)";
    assert!(rows(&o).contains(&format!("Server ns1.example.com: {lame}")), "{:?}", rows(&o));
}

#[tokio::test]
async fn a_bootstrap_that_knows_no_nameservers_for_the_name_gives_the_error_text() {
    let rec = FakeDns::start("").await;
    let err = CHECK.run(&Request::system("nosuch.example", T, &[rec.addr])).await;
    assert_eq!(err.unwrap_err(), "no nameservers found for nosuch.example");
}

#[tokio::test]
async fn a_bootstrap_that_never_answers_gives_the_no_resolver_text() {
    let rec = FakeDns::silent().await;
    let err = CHECK.run(&Request::system("example.com", Duration::from_millis(100), &[rec.addr])).await;
    assert_eq!(err.unwrap_err(), "no resolver could be asked for the nameservers of example.com");
}

#[tokio::test]
async fn a_zone_whose_parent_gives_no_referral_gives_the_no_referral_text() {
    let silent = FakeDns::silent().await;
    let err = run_on(silent.addr.port(), "example.com").await;
    assert_eq!(err.unwrap_err(), "none of the parent zone's servers returned a delegation for example.com");
}

#[tokio::test]
async fn the_request_s_query_timeout_limits_each_question() {
    let started = std::time::Instant::now();
    let silent = FakeDns::silent().await;
    let rec = FakeDns::start(BOOTSTRAP).await;
    let bootstrap = [rec.addr];
    let request = Request {
        seams: Seams { ns_port: silent.addr.port(), ..Seams::default() },
        ..Request::system("example.com", Duration::from_millis(100), &bootstrap)
    };
    assert!(CHECK.run(&request).await.is_err());
    assert!(started.elapsed() < Duration::from_secs(2), "the request's query timeout was not used");
}

#[tokio::test]
async fn a_top_level_name_gives_the_no_parent_text() {
    let server = FakeDns::start(ZONE).await.referral().authoritative();
    let err = run_on(server.addr.port(), "com").await;
    assert_eq!(err.unwrap_err(), "com is a top-level name: there is no parent zone to compare with");
}

#[test]
fn the_descriptor_names_the_row_the_kinds_it_runs_on_by_itself_and_what_it_owns() {
    assert_eq!(CHECK.label, "Delegation");
    assert_eq!(CHECK.automatic_for, [Kind::Domain, Kind::Email]);
    assert!(!CHECK.is_on_demand() && CHECK.on_demand.is_none() && !CHECK.takes_chosen_port);
    assert_eq!(CHECK.budget, (Duration::from_secs(20), Duration::from_secs(4)));
    assert_eq!(CHECK.owns, ["dns_delegation_", "dns_glue_", "dns_ns_"]);
    assert_eq!(CHECK.blind_spots.len(), 3);
}

/// Reads the real network. Run on a network that does not intercept DNS:
/// `cargo test -p zombo-core --test check_delegation -- --ignored`.
#[tokio::test]
#[ignore = "needs a real network"]
async fn live_a_real_domain_gives_a_row_or_a_delegation_error_text() {
    let bootstrap: [SocketAddr; 2] = ["1.1.1.1:53".parse().unwrap(), "8.8.8.8:53".parse().unwrap()];
    match CHECK.run(&Request::system("example.com", Duration::from_secs(4), &bootstrap)).await {
        Ok(o) => assert!(!o.facts.is_empty()),
        Err(e) => assert!(
            e.starts_with("no nameservers found for")
                || e.starts_with("no resolver could be asked")
                || e.starts_with("none of the parent zone's servers"),
            "{e}"
        ),
    }
}
