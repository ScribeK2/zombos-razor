#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod common;

use std::time::{Duration, UNIX_EPOCH};

use common::{FakeDns, dnssec_zone};
use zombo_core::{
    Severity,
    check::{Outcome, Request},
    dnssec::CHECK,
    propagation::Vantage,
};

const T: Duration = Duration::from_millis(500);
const APEX: &str = "cloudflare.com";
/// Inside the validity period of the real SOA signature in the fixture.
const SIGNED_AT: u64 = 1794141381 + 3600;

fn rows(f: &[zombo_core::check::Fact]) -> Vec<String> {
    f.iter().map(zombo_core::check::Fact::record).collect()
}

/// Run the DNSSEC Check against fakes: a recursive resolver that knows the zone's NS and `parent`
/// (its DS), one authoritative nameserver serving `zone`, and one validating resolver.
async fn run(parent: &str, zone: &str, at: u64) -> Result<Outcome, String> {
    let ns = FakeDns::start(zone).await.authoritative();
    let rec = FakeDns::start(&format!("{APEX}. 300 IN NS ns1.{APEX}.\nns1.{APEX}. 300 IN A 127.0.0.1\n{parent}")).await;
    let resolver = FakeDns::start(&format!("{APEX}. 300 IN A 192.0.2.1\n")).await.validating();
    let validating = [Vantage::resolver("Fake", "Test", resolver.addr)];
    CHECK
        .run(&Request {
            name: &format!("www.{APEX}"),
            query: T,
            bootstrap: &[rec.addr],
            ns_port: ns.addr.port(),
            now: UNIX_EPOCH + Duration::from_secs(at),
            validating: Some(&validating),
        })
        .await
}

#[tokio::test]
async fn a_healthy_signed_zone_gives_zone_resolver_ds_and_key_rows() {
    let z = dnssec_zone(APEX);
    let o = run(&z, &z, SIGNED_AT).await.unwrap();
    assert_eq!(
        rows(&o.facts),
        [
            "Zone: cloudflare.com",
            "Resolver Fake: SECURE",
            "DS record: key tag 2371, ECDSAP256SHA256 (13), matches a served key"
        ]
    );
    assert_eq!(o.details_title, "Keys by nameserver");
    assert_eq!(
        rows(&o.details),
        [
            "Key at ns1.cloudflare.com: key tag 34505, ECDSAP256SHA256 (13), flags 256",
            "Key at ns1.cloudflare.com: key tag 2371, ECDSAP256SHA256 (13), flags 257"
        ]
    );
    let found: Vec<_> = o.findings.iter().map(|f| (f.code, f.severity)).collect();
    assert_eq!(found, [("dnssec_secure", Severity::Ok)]);
    // The clock is the injected one: the signature has "another 2 days" at SIGNED_AT only.
    assert!(o.findings[0].message.contains("valid for another 2 days"), "{}", o.findings[0].message);
}

#[tokio::test]
async fn a_ds_that_matches_no_key_is_reported_as_unmatched() {
    let z = dnssec_zone(APEX);
    let parent = z.replace("2371 13 2 32996839", "2371 13 2 32996838");
    assert_ne!(parent, z, "the fixture's DS digest changed, so this test edits nothing");
    let o = run(&parent, &z, SIGNED_AT).await.unwrap();
    assert!(
        rows(&o.facts).contains(&"DS record: key tag 2371, ECDSAP256SHA256 (13), matches no served key".to_string()),
        "{:?}",
        o.facts
    );
    let found: Vec<_> = o.findings.iter().map(|f| (f.code, f.severity)).collect();
    assert_eq!(found, [("dnssec_ds_mismatch", Severity::Critical)]);
}

#[tokio::test]
async fn a_name_nobody_can_resolve_is_the_checks_own_error_text() {
    let request = Request::system("example.com", T, &[]);
    assert_eq!(CHECK.run(&request).await.unwrap_err(), "no resolver could be asked for the nameservers of example.com");
}
