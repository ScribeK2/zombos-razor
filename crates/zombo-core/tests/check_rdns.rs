#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! The Reverse DNS Check as the UI runs it: the machine's resolvers are a fake DNS server.
mod common;

use std::{net::SocketAddr, time::Duration};

use common::FakeDns;
use zombo_core::{
    Severity,
    check::{Fact, Outcome, Request, Seams},
    rdns::CHECK,
    target::Kind,
};

const T: Duration = Duration::from_millis(500);
const CONFIRMED: &str =
    "7.113.0.203.in-addr.arpa. 300 IN PTR mail.example.com.\nmail.example.com. 300 IN A 203.0.113.7\n";

fn rows(o: &Outcome) -> Vec<String> {
    o.facts.iter().map(Fact::record).collect()
}

fn found(o: &Outcome) -> Vec<(&'static str, Severity)> {
    o.findings.iter().map(|f| (f.code, f.severity)).collect()
}

async fn run(zone: &str, name: &str) -> Result<Outcome, String> {
    let dns = FakeDns::start(zone).await;
    let machine = [dns.addr];
    CHECK
        .run(&Request {
            seams: Seams { machine_resolvers: Some(&machine), ..Seams::default() },
            ..Request::system(name, T, &[])
        })
        .await
}

#[tokio::test]
async fn an_address_with_a_confirmed_ptr_gives_the_address_ptr_and_forward_rows() {
    let o = run(CONFIRMED, "203.0.113.7").await.unwrap();
    assert_eq!(
        rows(&o),
        [
            "Address: 203.0.113.7",
            "PTR question: 7.113.0.203.in-addr.arpa.",
            "PTR: mail.example.com",
            "Forward lookup of mail.example.com: 203.0.113.7, which confirms 203.0.113.7"
        ]
    );
    assert_eq!(found(&o), [("rdns_confirmed", Severity::Ok)]);
    assert!(o.details.is_empty());
}

#[tokio::test]
async fn an_address_with_no_ptr_says_none_and_warns() {
    let o = run("", "203.0.113.7").await.unwrap();
    assert!(rows(&o).contains(&"PTR: none".to_string()), "{:?}", rows(&o));
    assert_eq!(found(&o), [("rdns_no_ptr", Severity::Warning)]);
}

#[tokio::test]
async fn a_host_name_target_lists_its_addresses() {
    let o = run(CONFIRMED, "mail.example.com").await.unwrap();
    assert_eq!(rows(&o), ["Host: mail.example.com", "Address: 203.0.113.7"]);
    assert_eq!(found(&o), [("rdns_addresses", Severity::Info)]);
}

#[tokio::test]
async fn a_machine_with_no_resolver_gets_the_error_text() {
    let err = CHECK
        .run(&Request {
            seams: Seams { machine_resolvers: Some(&[]), ..Seams::default() },
            ..Request::system("203.0.113.7", T, &[])
        })
        .await;
    assert_eq!(err.unwrap_err(), "this machine has no DNS resolver configured");
}

#[tokio::test]
async fn a_resolver_that_never_answers_is_a_finding_not_an_error_after_one_query_timeout() {
    let started = std::time::Instant::now();
    let dns = FakeDns::silent().await;
    let machine = [dns.addr];
    let o = CHECK
        .run(&Request {
            seams: Seams { machine_resolvers: Some(&machine), ..Seams::default() },
            ..Request::system("203.0.113.7", Duration::from_millis(100), &[])
        })
        .await
        .unwrap();
    assert_eq!(found(&o), [("rdns_lookup_failed", Severity::Warning)]);
    assert!(started.elapsed() < Duration::from_secs(2), "the request's query timeout was not used");
}

#[test]
fn the_descriptor_names_the_row_the_kinds_it_runs_on_by_itself_and_what_it_owns() {
    assert_eq!(CHECK.label, "Reverse DNS");
    assert_eq!(CHECK.automatic_for, [Kind::Ip]);
    assert!(!CHECK.is_on_demand() && CHECK.on_demand.is_none() && !CHECK.takes_chosen_port);
    assert_eq!(CHECK.budget, (Duration::from_secs(20), Duration::from_secs(4)));
    assert_eq!(CHECK.owns, ["rdns_"]);
    assert_eq!(CHECK.blind_spots.len(), 3);
}

/// Reads the real resolvers. Run on a network that does not intercept DNS:
/// `cargo test -p zombo-core --test check_rdns -- --ignored`.
#[tokio::test]
#[ignore = "needs a real network"]
async fn live_a_real_address_gives_a_row_or_the_no_resolver_text() {
    let bootstrap: [SocketAddr; 0] = [];
    match CHECK.run(&Request::system("8.8.8.8", Duration::from_secs(3), &bootstrap)).await {
        Ok(o) => assert!(!o.facts.is_empty()),
        Err(e) => assert_eq!(e, "this machine has no DNS resolver configured"),
    }
}
