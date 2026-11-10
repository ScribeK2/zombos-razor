#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod common;

use std::time::Duration;

use common::{FakeDns, zone};
use hickory_proto::rr::RecordType;
use zombo_core::{
    Finding, Severity,
    lookup::{LOOKUP_TYPES, dns_lookup},
    lookup_findings::lookup_findings,
};

const T: Duration = Duration::from_millis(500);

async fn findings(zone_text: &str, target: &str, apex: bool, refuse: &[RecordType]) -> Vec<Finding> {
    let mut s = FakeDns::start(zone_text).await;
    for &t in refuse {
        s = s.refuse(t);
    }
    let r = dns_lookup(s.addr, target, &LOOKUP_TYPES, true, T).await.unwrap();
    lookup_findings(target, apex, &r)
}

fn one(fs: &[Finding], code: &str) -> Finding {
    fs.iter().find(|f| f.code == code).unwrap_or_else(|| panic!("no {code}; got {:?}", codes(fs))).clone()
}

fn codes(fs: &[Finding]) -> Vec<&'static str> {
    fs.iter().map(|f| f.code).collect()
}

#[tokio::test]
async fn a_healthy_domain_resolves_and_has_mail_exchangers() {
    let fs = findings(&zone("example"), "example.com", true, &[]).await;
    assert_eq!(codes(&fs), ["dns_resolves", "dns_mx"]);
    assert!(fs.iter().all(|f| f.severity == Severity::Ok));
    assert_eq!(one(&fs, "dns_resolves").message, "example.com resolves to 2 addresses.");
    assert_eq!(one(&fs, "dns_mx").message, "example.com has 1 MX record.");
}

#[tokio::test]
async fn nxdomain_is_critical_and_the_only_finding() {
    let fs = findings(&zone("example"), "nope.test", true, &[]).await;
    assert_eq!(codes(&fs), ["dns_nxdomain"]);
    let f = &fs[0];
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.title, "Name does not exist");
    assert_eq!(f.message, "The resolver answered NXDOMAIN: nope.test does not exist in DNS.");
    assert_eq!(
        f.recommendation.as_deref(),
        Some("Check the spelling, then whether the domain is registered and its nameservers are delegated.")
    );
}

#[tokio::test]
async fn a_domain_with_no_address_records() {
    let z = "example.com. 300 IN NS ns.example.net.\nexample.com. 300 IN MX 10 mail.example.net.";
    let f = one(&findings(z, "example.com", true, &[]).await, "dns_no_address");
    assert_eq!((f.severity, f.title.as_ref()), (Severity::Warning, "No address records"));
    assert_eq!(
        f.message,
        "example.com has no A or AAAA records, so websites and other services on it can't be reached."
    );
    assert!(f.recommendation.is_some());
}

#[tokio::test]
async fn a_domain_with_no_mx() {
    let z = "example.com. 300 IN NS ns.example.net.\nexample.com. 300 IN A 192.0.2.1";
    let f = one(&findings(z, "example.com", true, &[]).await, "dns_no_mx");
    assert_eq!((f.severity, f.title.as_ref()), (Severity::Warning, "No MX records"));
    assert_eq!(f.message, "Mail to example.com falls back to its address record, and most senders won't deliver it.");
}

#[tokio::test]
async fn a_null_mx_declares_no_mail() {
    let z = "example.com. 300 IN NS ns.example.net.\nexample.com. 300 IN A 192.0.2.1\nexample.com. 300 IN MX 0 .";
    let f = one(&findings(z, "example.com", true, &[]).await, "dns_null_mx");
    assert_eq!((f.severity, f.title.as_ref()), (Severity::Info, "Declares no mail"));
    assert_eq!(f.message, "example.com publishes a null MX (RFC 7505): it accepts no email.");
    assert!(f.recommendation.is_none());
}

#[tokio::test]
async fn a_domain_with_no_ns() {
    let z = "example.com. 300 IN A 192.0.2.1\nexample.com. 300 IN MX 10 mail.example.net.";
    let f = one(&findings(z, "example.com", true, &[]).await, "dns_no_ns");
    assert_eq!((f.severity, f.title.as_ref()), (Severity::Critical, "No NS records"));
    assert_eq!(f.message, "The resolver returned no nameservers for example.com.");
}

#[tokio::test]
async fn a_cname_at_the_apex_is_critical() {
    let z = "example.com. 300 IN CNAME other.example.net.";
    let fs = findings(z, "example.com", true, &[]).await;
    let f = one(&fs, "dns_cname_at_apex");
    assert_eq!((f.severity, f.title.as_ref()), (Severity::Critical, "CNAME at the zone apex"));
    assert_eq!(
        f.message,
        "example.com is a CNAME to other.example.net.. A CNAME can't coexist with the NS, SOA and MX records the apex needs."
    );
    assert!(!codes(&fs).contains(&"dns_no_address"), "a CNAME is not a missing address");
}

#[tokio::test]
async fn a_hostname_is_not_held_to_the_apex_rules() {
    let fs = findings(&zone("example"), "www.example.com", false, &[]).await;
    for c in ["dns_no_mx", "dns_no_ns", "dns_cname_at_apex", "dns_mx", "dns_null_mx"] {
        assert!(!codes(&fs).contains(&c), "{c} applied to a hostname: {:?}", codes(&fs));
    }
}

#[tokio::test]
async fn a_failed_query_is_not_reported_as_a_missing_record() {
    let z = "example.com. 300 IN TXT \"v=spf1 -all\"";
    let refuse = [RecordType::A, RecordType::AAAA, RecordType::MX, RecordType::NS];
    let fs = findings(z, "example.com", true, &refuse).await;
    for wrong in ["dns_no_address", "dns_no_mx", "dns_no_ns"] {
        assert!(!codes(&fs).contains(&wrong), "{wrong} reported although that query failed: {:?}", codes(&fs));
    }
    let f = one(&fs, "dns_query_errors");
    assert_eq!((f.severity, f.title.as_ref()), (Severity::Info, "Some lookups failed"));
    assert_eq!(
        f.message,
        "These record types could not be queried, so their absence above is not conclusive: A, AAAA, MX, NS."
    );
}
