#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! The Blacklist Check as the UI runs it: the machine's resolver is a fake DNS server that lists
//! `203.0.113.7` on PSBL, the way the `127.0.0.2` test entries of the real lists do.
mod common;

use std::{net::SocketAddr, time::Duration};

use common::FakeDns;
use zombo_core::{
    Severity,
    blacklist::{CHECK, DNSBLS},
    check::{Fact, Outcome, Request},
};

const T: Duration = Duration::from_millis(500);
const PSBL: &str = "7.113.0.203.psbl.surriel.com. 300 IN A 127.0.0.2\n";

fn rows(o: &Outcome) -> Vec<String> {
    o.facts.iter().map(Fact::record).collect()
}

fn found(o: &Outcome) -> Vec<(&'static str, Severity)> {
    o.findings.iter().map(|f| (f.code, f.severity)).collect()
}

async fn run_with(zone: &str, name: &str, query: Duration) -> Result<Outcome, String> {
    let dns = FakeDns::start(zone).await;
    let machine = [dns.addr];
    CHECK.run(&Request { machine_resolvers: Some(&machine), ..Request::system(name, query, &[]) }).await
}

async fn run(zone: &str, name: &str) -> Result<Outcome, String> {
    run_with(zone, name, T).await
}

#[tokio::test]
async fn a_clean_address_is_not_listed_on_any_ip_list() {
    let o = run("", "203.0.113.7").await.unwrap();
    assert_eq!(rows(&o), ["203.0.113.7 (address, target): not listed on any of 8 lists"]);
    assert_eq!(found(&o), [("blacklist_clean", Severity::Ok)]);
    assert_eq!(o.details_title, "Every list's answer");
    assert_eq!(o.details.len(), 8);
    assert!(o.details.iter().all(|d| d.value == "not listed"));
}

#[tokio::test]
async fn a_listed_address_names_the_list_and_keeps_every_answer_in_the_details() {
    let o = run(PSBL, "203.0.113.7").await.unwrap();
    assert_eq!(rows(&o), ["203.0.113.7 (address, target): listed on 1 of 8 lists", "Listed on PSBL: 127.0.0.2"]);
    assert_eq!(found(&o), [("blacklist_listed", Severity::Warning)]);
    assert!(o.details.iter().any(|d| d.record() == "PSBL for 203.0.113.7: listed 127.0.0.2"));
    assert_eq!(o.details.len(), 8);
}

#[tokio::test]
async fn a_machine_with_no_resolver_gets_the_error_text() {
    let err = CHECK.run(&Request { machine_resolvers: Some(&[]), ..Request::system("203.0.113.7", T, &[]) }).await;
    assert_eq!(err.unwrap_err(), "this machine has no DNS resolver configured");
}

#[tokio::test]
async fn the_requests_query_timeout_does_not_change_the_outcome() {
    let patient = run_with(PSBL, "203.0.113.7", Duration::from_secs(5)).await.unwrap();
    let impatient = run_with(PSBL, "203.0.113.7", Duration::ZERO).await.unwrap();
    assert_eq!(rows(&impatient), rows(&patient));
    assert_eq!(found(&impatient), found(&patient));
    assert_eq!(impatient.records(), patient.records());
}

#[test]
fn the_descriptor_runs_only_on_demand_with_its_own_limits_and_prefix() {
    assert_eq!(CHECK.label, "Blacklist");
    assert!(CHECK.automatic_for.is_empty() && CHECK.is_on_demand() && !CHECK.takes_chosen_port);
    assert_eq!(CHECK.budget, (Duration::from_secs(25), Duration::from_secs(25)));
    assert_eq!(CHECK.owns, ["blacklist_"]);
    assert_eq!(CHECK.blind_spots.len(), 4);
    let brief = CHECK.on_demand.unwrap();
    assert_eq!(brief.run_label, "Run blacklist check");
    assert_eq!(brief.note, None);
    assert!(brief.what.starts_with("Asks public blocklists"));
}

#[test]
fn the_brief_states_the_number_of_lists_the_table_holds() {
    let contacts = CHECK.on_demand.unwrap().contacts;
    assert!(contacts.contains(&format!("sends {} questions per address", DNSBLS.len())), "{contacts}");
}

/// Reads the real resolvers. Run on a network that does not intercept DNS:
/// `cargo test -p zombo-core --test check_blacklist -- --ignored`.
#[tokio::test]
#[ignore = "needs a real network"]
async fn live_a_real_address_gives_a_row_or_the_no_resolver_text() {
    let bootstrap: [SocketAddr; 0] = [];
    match CHECK.run(&Request::system("127.0.0.2", Duration::from_secs(3), &bootstrap)).await {
        Ok(o) => assert!(!o.facts.is_empty()),
        Err(e) => assert_eq!(e, "this machine has no DNS resolver configured"),
    }
}
