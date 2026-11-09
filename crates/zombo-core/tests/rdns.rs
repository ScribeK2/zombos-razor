mod common;
#[path = "common/scripted.rs"]
mod scripted;

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use common::{FakeDns, zone};
use hickory_proto::rr::RecordType;
use scripted::{Reply, a, cname, ptr, serve};
use zombo_core::{
    Finding, Severity,
    rdns::{RdnsResult, check_rdns, rdns_findings, reverse_name},
};

const T: Duration = Duration::from_millis(500);

fn fixture(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../testdata/rdns/{name}.zone"));
    std::fs::read_to_string(p).unwrap()
}

async fn run_on(server: SocketAddr, target: &str) -> (RdnsResult, Vec<Finding>) {
    let r = check_rdns(&[server], target, T).await;
    let f = rdns_findings(&r);
    (r, f)
}

async fn run(zone_text: &str, target: &str) -> (RdnsResult, Vec<Finding>) {
    run_on(FakeDns::start(zone_text).await.addr, target).await
}

fn codes(fs: &[Finding]) -> Vec<&'static str> {
    fs.iter().map(|f| f.code).collect()
}

fn ptrs(r: &RdnsResult) -> &[zombo_core::rdns::Ptr] {
    match r {
        RdnsResult::Ip { ptrs, .. } => ptrs,
        RdnsResult::Host { .. } => panic!("not an IP result"),
    }
}

#[test]
fn reverse_names_for_both_families() {
    assert_eq!(reverse_name("203.0.113.7".parse().unwrap()), "7.113.0.203.in-addr.arpa.");
    let v6 = format!("1.{}8.b.d.0.1.0.0.2.ip6.arpa.", "0.".repeat(23));
    assert_eq!(reverse_name("2001:db8::1".parse().unwrap()), v6);
    assert_eq!(reverse_name("fe80::abcd".parse().unwrap()), "d.c.b.a.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.");
}

#[tokio::test]
async fn a_ptr_that_resolves_back_is_confirmed() {
    let (r, fs) = run(&fixture("confirmed"), "203.0.113.7").await;
    let p = &ptrs(&r)[0];
    assert_eq!((p.name.as_str(), p.confirmed), ("mail.example.com", true));
    assert_eq!(codes(&fs), ["rdns_confirmed"]);
    assert_eq!(fs[0].severity, Severity::Ok);
}

#[tokio::test]
async fn an_address_without_a_ptr_is_reported() {
    let (r, fs) = run(&fixture("confirmed"), "203.0.113.8").await;
    assert!(ptrs(&r).is_empty());
    assert_eq!(codes(&fs), ["rdns_no_ptr"]);
    assert_eq!(fs[0].severity, Severity::Warning);
}

#[tokio::test]
async fn a_ptr_resolving_to_another_address_fails_forward_confirmation() {
    let (r, fs) = run(&fixture("mismatch"), "203.0.113.7").await;
    assert!(!ptrs(&r)[0].confirmed);
    assert_eq!(codes(&fs), ["rdns_not_confirmed"]);
    assert_eq!(fs[0].severity, Severity::Warning);
    assert!(fs[0].message.contains("resolves to 203.0.113.99, not 203.0.113.7") && fs[0].message.contains("FCrDNS"), "{}", fs[0].message);
}

#[tokio::test]
async fn a_ptr_name_with_no_address_fails_forward_confirmation() {
    let (_, fs) = run(&fixture("no_forward"), "203.0.113.7").await;
    assert_eq!(codes(&fs), ["rdns_not_confirmed"]);
    assert!(fs[0].message.contains("has no A record"), "{}", fs[0].message);
}

#[tokio::test]
async fn several_ptrs_are_reported_and_each_is_confirmed() {
    let (r, fs) = run(&fixture("multiple"), "203.0.113.7").await;
    assert_eq!(ptrs(&r).len(), 2);
    assert_eq!(codes(&fs), ["rdns_multiple_ptr", "rdns_confirmed"]);
}

#[tokio::test]
async fn one_bad_name_among_several_denies_confirmation() {
    let text = format!("{}\n7.113.0.203.in-addr.arpa. 300 IN PTR gone.example.com.", fixture("confirmed"));
    let (_, fs) = run(&text, "203.0.113.7").await;
    assert_eq!(codes(&fs), ["rdns_multiple_ptr", "rdns_not_confirmed"]);
}

#[tokio::test]
async fn a_name_that_embeds_the_address_looks_generated() {
    let (_, fs) = run(&fixture("generic"), "203.0.113.7").await;
    assert_eq!(codes(&fs), ["rdns_generic_name", "rdns_confirmed"]);
    assert_eq!(fs[0].severity, Severity::Info);
}

#[tokio::test]
async fn ipv6_is_asked_in_nibble_form_and_confirmed_by_aaaa() {
    let (r, fs) = run(&fixture("ipv6"), "2001:db8::1").await;
    assert_eq!(ptrs(&r)[0].name, "mail6.example.com");
    assert_eq!(codes(&fs), ["rdns_confirmed"]);
}

#[tokio::test]
async fn a_silent_resolver_is_a_failed_lookup_not_a_missing_ptr() {
    let s = FakeDns::silent().await;
    let (_, fs) = run_on(s.addr, "203.0.113.7").await;
    assert_eq!(codes(&fs), ["rdns_lookup_failed"]);
}

#[tokio::test]
async fn a_silent_forward_lookup_is_unknown_not_a_failure() {
    let server = serve(|name, t| match (name, t) {
        ("7.113.0.203.in-addr.arpa", RecordType::PTR) => Reply::Answers(vec![ptr(name, "mail.example.com.")]),
        _ => Reply::Silent,
    })
    .await;
    let (r, fs) = run_on(server, "203.0.113.7").await;
    assert!(ptrs(&r)[0].forward_error.is_some());
    assert_eq!(codes(&fs), ["rdns_forward_unknown"]);
}

#[tokio::test]
async fn a_host_reports_each_address() {
    let (r, fs) = run(&zone("example"), "example.com").await;
    let RdnsResult::Host { addresses, errors, .. } = &r else { panic!("{r:?}") };
    assert_eq!(addresses.iter().map(ToString::to_string).collect::<Vec<_>>(), ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]);
    assert!(errors.is_empty());
    assert_eq!(codes(&fs), ["rdns_addresses"]);
    assert!(fs[0].message.contains("93.184.216.34, 2606:2800:220:1:248:1893:25c8:1946"));
}

#[tokio::test]
async fn a_host_with_no_address_is_reported() {
    let (_, fs) = run(&zone("example"), "nothing.example.com").await;
    assert_eq!(codes(&fs), ["rdns_no_address"]);
}

#[tokio::test]
async fn a_host_on_a_silent_resolver_is_a_failed_lookup() {
    let s = FakeDns::silent().await;
    let (_, fs) = run_on(s.addr, "example.com").await;
    assert_eq!(codes(&fs), ["rdns_lookup_failed"]);
}

// Hostile replies.

#[tokio::test]
async fn a_reply_with_no_answers_means_no_ptr() {
    let server = serve(|_, _| Reply::Answers(vec![])).await;
    let (_, fs) = run_on(server, "203.0.113.7").await;
    assert_eq!(codes(&fs), ["rdns_no_ptr"]);
}

#[tokio::test]
async fn a_cname_in_front_of_the_ptr_is_followed_by_the_resolver_and_read() {
    // RFC 2317 classless delegation: the reverse name is an alias of the name that holds the PTR.
    let server = serve(|name, t| match (name, t) {
        ("7.113.0.203.in-addr.arpa", RecordType::PTR) => {
            Reply::Answers(vec![cname(name, "7.0-25.113.0.203.in-addr.arpa."), ptr("7.0-25.113.0.203.in-addr.arpa.", "mail.example.com.")])
        }
        ("mail.example.com", RecordType::A) => Reply::Answers(vec![a(name, "203.0.113.7")]),
        _ => Reply::NxDomain,
    })
    .await;
    let (_, fs) = run_on(server, "203.0.113.7").await;
    assert_eq!(codes(&fs), ["rdns_confirmed"]);
}

#[tokio::test]
async fn a_cname_instead_of_an_address_does_not_confirm() {
    let server = serve(|name, t| match (name, t) {
        ("7.113.0.203.in-addr.arpa", RecordType::PTR) => Reply::Answers(vec![ptr(name, "mail.example.com.")]),
        ("mail.example.com", RecordType::A) => Reply::Answers(vec![cname(name, "elsewhere.test.")]),
        _ => Reply::NxDomain,
    })
    .await;
    let (_, fs) = run_on(server, "203.0.113.7").await;
    assert_eq!(codes(&fs), ["rdns_not_confirmed"]);
}

#[tokio::test]
async fn a_flood_of_ptr_names_is_bounded() {
    let server = serve(|name, t| match (name, t) {
        ("7.113.0.203.in-addr.arpa", RecordType::PTR) => Reply::Answers((0..60).map(|i| ptr(name, &format!("h{i}.example.com."))).collect()),
        _ => Reply::NxDomain,
    })
    .await;
    let (r, _) = run_on(server, "203.0.113.7").await;
    assert_eq!(ptrs(&r).len(), 8);
}

#[tokio::test]
async fn a_flood_of_addresses_for_a_host_is_bounded() {
    let server = serve(|name, t| match t {
        RecordType::A => Reply::Answers((0..100).map(|i| a(name, &format!("198.51.100.{i}"))).collect()),
        _ => Reply::NxDomain,
    })
    .await;
    let (r, _) = run_on(server, "example.com").await;
    let RdnsResult::Host { addresses, .. } = r else { panic!() };
    assert_eq!(addresses.len(), 32);
}

#[tokio::test]
async fn control_characters_in_a_ptr_name_do_not_reach_a_message() {
    use hickory_proto::rr::{Name, RData, Record, rdata::PTR};
    let server = serve(|name, t| match t {
        RecordType::PTR => {
            let evil = Name::from_labels([&b"bad\x07name"[..], b"example", b"com"]).unwrap();
            Reply::Answers(vec![Record::from_rdata(Name::from_ascii(name).unwrap(), 300, RData::PTR(PTR(evil)))])
        }
        _ => Reply::NxDomain,
    })
    .await;
    let (r, fs) = run_on(server, "203.0.113.7").await;
    assert_eq!(ptrs(&r).len(), 1);
    assert!(!ptrs(&r)[0].name.chars().any(char::is_control), "{:?}", ptrs(&r)[0].name);
    assert!(fs.iter().all(|f| !f.message.chars().any(char::is_control) && !f.title.chars().any(char::is_control)));
}
