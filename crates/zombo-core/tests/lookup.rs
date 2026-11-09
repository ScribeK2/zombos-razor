mod common;

use std::time::Duration;

use common::{FakeDns, zone};
use hickory_proto::rr::RecordType;
use zombo_core::lookup::{LOOKUP_TYPES, Rcode, dns_lookup};

const T: Duration = Duration::from_millis(500);

fn texts(r: &zombo_core::lookup::LookupResult, t: &str) -> Vec<String> {
    r.records.get(t).map(|v| v.iter().map(|x| x.text.clone()).collect()).unwrap_or_default()
}

/// The exact strings the Go engine produced (miekg presentation format minus the header).
#[tokio::test]
async fn records_read_the_same_as_in_the_go_engine() {
    let s = FakeDns::start(&zone("example")).await;
    let r = dns_lookup(s.addr, "example.com", &LOOKUP_TYPES, T).await.unwrap();
    assert_eq!(r.rcode, Rcode::NoError);
    assert_eq!(texts(&r, "A"), ["93.184.216.34"]);
    assert_eq!(texts(&r, "AAAA"), ["2606:2800:220:1:248:1893:25c8:1946"]);
    assert_eq!(texts(&r, "MX"), ["10 mail.example.com."]);
    assert_eq!(texts(&r, "NS"), ["a.iana-servers.net."]);
    assert_eq!(texts(&r, "TXT"), ["\"v=spf1 -all\""]);
    assert_eq!(texts(&r, "SOA"), ["ns.icann.org. noc.dns.icann.org. 2024 7200 3600 1209600 3600"]);
    assert_eq!(texts(&r, "CAA"), ["0 issue \"letsencrypt.org\""]);
    assert!(r.errors.is_empty(), "{:?}", r.errors);
}

#[tokio::test]
async fn a_cname_in_front_of_an_address_is_not_an_address() {
    let s = FakeDns::start(&zone("example")).await;
    let r = dns_lookup(s.addr, "www.example.com", &[RecordType::A, RecordType::CNAME], T).await.unwrap();
    assert_eq!(texts(&r, "CNAME"), ["example.com."]);
    assert!(texts(&r, "A").is_empty());
}

#[tokio::test]
async fn nxdomain_is_an_answer_not_a_failure() {
    let s = FakeDns::start(&zone("example")).await;
    let r = dns_lookup(s.addr, "nope.test", &LOOKUP_TYPES, T).await.unwrap();
    assert_eq!(r.rcode, Rcode::NxDomain);
}

#[tokio::test]
async fn a_refused_type_is_reported_and_the_rest_still_answer() {
    let s = FakeDns::start(&zone("example")).await.refuse(RecordType::CAA);
    let r = dns_lookup(s.addr, "example.com", &LOOKUP_TYPES, T).await.unwrap();
    assert_eq!(r.errors.keys().collect::<Vec<_>>(), ["CAA"]);
    assert_eq!(texts(&r, "MX"), ["10 mail.example.com."]);
}

#[tokio::test]
async fn a_silent_server_fails_the_lookup() {
    let s = FakeDns::silent().await;
    assert!(dns_lookup(s.addr, "example.com", &LOOKUP_TYPES, Duration::from_millis(200)).await.is_err());
}

#[tokio::test]
async fn an_oversized_udp_answer_is_retried_over_tcp() {
    // 40 TXT records of 60 bytes: well over the 1232-byte EDNS payload.
    let zone: String = (0..40).map(|i| format!("big.example.com. 300 IN TXT \"{i:02}{}\"\n", "x".repeat(58))).collect();
    let s = FakeDns::start(&zone).await;
    let r = dns_lookup(s.addr, "big.example.com", &[RecordType::TXT], T).await.unwrap();
    assert_eq!(r.records["TXT"].len(), 40);
}

#[tokio::test]
async fn txt_with_quotes_and_several_strings_reads_like_the_go_engine() {
    let s = FakeDns::start("t.example.com. 60 IN TXT \"a b\" \"c\\\"d\"\n").await;
    let r = dns_lookup(s.addr, "t.example.com", &[RecordType::TXT], T).await.unwrap();
    assert_eq!(texts(&r, "TXT"), ["\"a b\" \"c\\\"d\""]);
}
