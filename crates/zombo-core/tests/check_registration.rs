#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! The Registration Check as the UI runs it: the registries are fake RDAP and WHOIS servers that the
//! request's `endpoints` point at, and the proxy is the request's `proxy`.
#[path = "common/registry.rs"]
mod registry;

use std::time::Duration;

use registry::{FakeHttp, FakeWhois, Reply, rdap_domain, silent};
use time::OffsetDateTime;
use zombo_core::{
    Severity,
    check::{Fact, Outcome, Request, Seams},
    registration::{CHECK, Endpoints, RegDate},
    target::Kind,
};

const T: Duration = Duration::from_secs(5);
const CLOSED: &str = "127.0.0.1:1";

fn rows(o: &Outcome) -> Vec<String> {
    o.facts.iter().map(Fact::record).collect()
}

fn found(o: &Outcome) -> Vec<(&'static str, Severity)> {
    o.findings.iter().map(|f| (f.code, f.severity)).collect()
}

/// The `.com` RDAP base is `base`; WHOIS is a closed port, so no test reaches the network.
fn rdap_at(base: &str) -> Endpoints {
    Endpoints {
        rdap: [("com".to_string(), base.to_string())].into(),
        whois: [("com".to_string(), CLOSED.to_string())].into(),
        whois_iana: CLOSED.into(),
        ..Endpoints::default()
    }
}

/// `.test` has no RDAP service, so only WHOIS at `whois` can answer.
fn whois_at(whois: &str) -> Endpoints {
    Endpoints {
        whois: [("test".to_string(), whois.to_string())].into(),
        whois_iana: CLOSED.into(),
        ..Endpoints::default()
    }
}

async fn run(name: &str, endpoints: &Endpoints, query: Duration) -> Result<Outcome, String> {
    CHECK
        .run(&Request {
            seams: Seams { endpoints: Some(endpoints), ..Seams::default() },
            ..Request::system(name, query, &[])
        })
        .await
}

#[tokio::test]
async fn a_registered_domain_gives_the_registry_rows_and_one_ok_finding() {
    let expires = OffsetDateTime::now_utc() + time::Duration::days(365);
    let rdap = FakeHttp::domain(200, rdap_domain(expires, &[])).await;
    let o = run("example.com", &rdap_at(&rdap.base), T).await.unwrap();
    assert_eq!(
        rows(&o),
        [
            "Domain: example.com".to_string(),
            "Registered: yes".into(),
            "Registrar: RESERVED-Internet Assigned Numbers Authority".into(),
            "Created: 1995-08-14T04:00:00Z".into(),
            "Updated: 2024-08-14T07:01:34Z".into(),
            format!("Expires: {}", RegDate::At(expires)),
            "Status: clientTransferProhibited".into(),
            "Nameserver: a.iana-servers.net".into(),
            "Nameserver: b.iana-servers.net".into(),
            "DNSSEC: signed".into(),
        ]
    );
    assert_eq!(found(&o), [("registration_ok", Severity::Ok)]);
    assert!(o.details.is_empty());
}

#[tokio::test]
async fn a_name_below_the_domain_is_asked_and_reported_as_its_registrable_domain() {
    let expires = OffsetDateTime::now_utc() + time::Duration::days(365);
    let rdap = FakeHttp::domain(200, rdap_domain(expires, &[])).await;
    let o = run("www.example.com", &rdap_at(&rdap.base), T).await.unwrap();
    assert_eq!(rows(&o)[0], "Domain: example.com");
    assert_eq!(rdap.paths(), ["/domain/example.com"]);
}

#[tokio::test]
async fn a_domain_the_registry_does_not_know_is_two_rows_and_one_critical_finding() {
    let rdap = FakeHttp::domain(404, "").await;
    let o = run("example.com", &rdap_at(&rdap.base), T).await.unwrap();
    assert_eq!(rows(&o), ["Domain: example.com", "Registered: no"]);
    assert_eq!(found(&o), [("registration_not_registered", Severity::Critical)]);
}

#[tokio::test]
async fn a_name_that_is_not_a_domain_gives_the_bad_name_text() {
    let err = run("localhost", &rdap_at(CLOSED), T).await.unwrap_err();
    assert_eq!(err, "\"localhost\" is not a valid domain name");
}

#[tokio::test]
async fn neither_registry_answering_gives_both_reasons_in_one_text() {
    let whois = FakeWhois::reply("").await;
    let err = run("nope.test", &whois_at(&whois.addr), T).await.unwrap_err();
    assert_eq!(err, format!("RDAP: no RDAP service for .test; WHOIS: empty reply from WHOIS server {}", whois.addr));

    let rdap = FakeHttp::domain(502, "").await;
    let whois = FakeWhois::reply("").await;
    let ep = Endpoints { whois: [("com".to_string(), whois.addr.clone())].into(), ..rdap_at(&rdap.base) };
    let err = run("example.com", &ep, T).await.unwrap_err();
    assert_eq!(
        err,
        format!("RDAP: RDAP server answered 502 Bad Gateway; WHOIS: empty reply from WHOIS server {}", whois.addr)
    );
}

#[tokio::test]
async fn the_requests_query_time_is_the_whole_lookups_limit() {
    let whois = silent().await;
    let started = std::time::Instant::now();
    let err = run("nope.test", &whois_at(&whois), Duration::from_millis(300)).await.unwrap_err();
    assert_eq!(err, "timed out");
    assert!(started.elapsed() < Duration::from_secs(3), "the request's query time was not the limit");
}

#[tokio::test]
async fn the_requests_proxy_carries_the_rdap_lookup() {
    let proxy = FakeHttp::start(|_| Reply::new(403, "")).await;
    let ep = rdap_at("http://127.0.0.1:1/");
    let request = Request {
        proxy: Some(&proxy.base),
        seams: Seams { endpoints: Some(&ep), ..Seams::default() },
        ..Request::system("example.com", T, &[])
    };
    let err = CHECK.run(&request).await.unwrap_err();
    assert_eq!(proxy.paths(), ["127.0.0.1:1"], "the proxy was asked to CONNECT to the RDAP server");
    assert!(err.contains("CONNECT proxy failed"), "{err}");
}

#[tokio::test]
async fn with_no_proxy_in_the_request_the_lookup_does_not_reach_one() {
    let proxy = FakeHttp::domain(200, "{}").await;
    let ep = rdap_at("http://127.0.0.1:1/");
    assert!(run("example.com", &ep, T).await.is_err());
    assert_eq!(proxy.hits(), 0);
}

#[tokio::test]
async fn a_proxy_that_the_endpoints_carry_is_kept_when_the_request_names_none() {
    let proxy = FakeHttp::start(|_| Reply::new(403, "")).await;
    let ep = Endpoints { proxy: Some(proxy.base.clone()), ..rdap_at("http://127.0.0.1:1/") };
    assert!(run("example.com", &ep, T).await.is_err());
    assert_eq!(proxy.paths(), ["127.0.0.1:1"]);
}

#[test]
fn the_descriptor_names_the_row_the_kinds_it_runs_on_by_itself_and_what_it_owns() {
    assert_eq!(CHECK.label, "Registration");
    assert_eq!(CHECK.automatic_for, [Kind::Domain, Kind::Hostname, Kind::Email]);
    assert!(!CHECK.is_on_demand() && CHECK.on_demand.is_none() && !CHECK.takes_chosen_port);
    assert_eq!(CHECK.budget, (Duration::from_secs(15), Duration::from_secs(12)));
    assert_eq!(CHECK.owns, ["registration_"]);
    assert_eq!(CHECK.blind_spots.len(), 3);
}

/// Reads the real network. Run on a network that does not intercept DNS:
/// `cargo test -p zombo-core --test check_registration -- --ignored`.
#[tokio::test]
#[ignore = "needs a real network"]
async fn live_a_real_domain_gives_a_row_or_a_registration_error_text() {
    match CHECK.run(&Request::system("example.com", Duration::from_secs(12), &[])).await {
        Ok(o) => assert_eq!(rows(&o)[0], "Domain: example.com"),
        Err(e) => assert!(e == "timed out" || e.starts_with("RDAP: "), "{e}"),
    }
}
