//! The authoritative Vantage: nameservers asked directly, with recursion off.

mod common;

use std::time::Duration;

use common::{FakeDns, zone};
use zombo_core::{
    Finding, Severity,
    propagation::{Agreement, Scope, Vantage, discover_nameservers, propagation_findings, propagation_with},
};

const T: Duration = Duration::from_millis(500);

fn r(name: &str, s: &FakeDns) -> Vantage {
    Vantage::resolver(name, "Test", s.addr)
}
fn ns(name: &str, s: &FakeDns) -> Vantage {
    Vantage::nameserver(name, s.addr)
}
fn code<'a>(fs: &'a [Finding], c: &str) -> Option<&'a Finding> {
    fs.iter().find(|f| f.code == c)
}

async fn run(resolvers: &[Vantage], nameservers: &[Vantage]) -> (zombo_core::propagation::PropagationResult, Vec<Finding>) {
    let res = propagation_with(resolvers, nameservers, "example.com", Scope::All, Duration::from_millis(300), |_| {}).await.unwrap();
    let fs = propagation_findings("example.com", &res);
    (res, fs)
}

#[tokio::test]
async fn resolvers_serving_old_records_are_called_cached_not_broken() {
    let (ns1, ns2) = (FakeDns::start(&zone("moved_mx")).await.authoritative(), FakeDns::start(&zone("moved_mx")).await.authoritative());
    let (fresh, old) = (FakeDns::start(&zone("moved_mx")).await, FakeDns::start(&zone("example")).await);
    let (res, fs) = run(&[r("Fresh", &fresh), r("Old", &old)], &[ns("ns1", &ns1), ns("ns2", &ns2)]).await;
    assert_eq!(res.stale["MX"], ["Old"], "{:?}", res.stale);
    assert!(res.stale.keys().all(|k| k == "MX"), "{:?}", res.stale);
    assert_eq!(res.agreement, Agreement::Cached);
    let f = code(&fs, "dns_propagation_stale_cache").expect("stale cache finding");
    assert_eq!(f.severity, Severity::Info);
    assert!(f.message.contains("Old") && !f.message.contains("Fresh"), "{}", f.message);
    assert!(f.message.contains("5 minutes"), "the stale resolver's remaining TTL (300 s): {}", f.message);
    assert!(code(&fs, "dns_authoritative_mismatch").is_none());
}

#[tokio::test]
async fn everything_matching_the_nameservers_says_so() {
    let ns1 = FakeDns::start(&zone("example")).await.authoritative();
    let (a, b) = (FakeDns::start(&zone("example")).await, FakeDns::start(&zone("example")).await);
    let (res, fs) = run(&[r("A", &a), r("B", &b)], &[ns("ns1", &ns1)]).await;
    assert!(res.stale.is_empty() && res.ns_disagree.is_empty());
    assert!(code(&fs, "dns_authoritative_consistent").is_some(), "{fs:?}");
    assert_eq!(res.agreement, Agreement::Agree);
}

/// example.zone has serial 2024, moved_mx.zone 2025.
#[tokio::test]
async fn a_nameserver_on_an_older_serial_is_behind_not_broken() {
    let (ns1, ns2) = (FakeDns::start(&zone("moved_mx")).await.authoritative(), FakeDns::start(&zone("example")).await.authoritative());
    let a = FakeDns::start(&zone("example")).await;
    let (res, fs) = run(&[r("A", &a)], &[ns("ns1", &ns1), ns("ns2", &ns2)]).await;
    assert_eq!(res.ns_disagree, ["MX"]);
    assert!(res.stale.is_empty(), "no truth to compare against: {:?}", res.stale);
    assert_eq!(res.agreement, Agreement::NameserversDiffer);
    let f = code(&fs, "dns_authoritative_behind").expect("behind finding");
    assert_eq!(f.severity, Severity::Warning);
    assert!(f.message.contains("ns2") && f.message.contains("2024") && f.message.contains("2025"), "{}", f.message);
    assert!(f.message.contains("2 hours"), "the SOA refresh interval (7200 s): {}", f.message);
    assert!(code(&fs, "dns_authoritative_mismatch").is_none(), "one alarm, not two");
}

#[tokio::test]
async fn the_same_serial_with_different_data_means_the_serial_was_not_bumped() {
    let same_serial = zone("moved_mx").replace("2025 7200", "2024 7200");
    let (ns1, ns2) = (FakeDns::start(&same_serial).await.authoritative(), FakeDns::start(&zone("example")).await.authoritative());
    let a = FakeDns::start(&zone("example")).await;
    let (res, fs) = run(&[r("A", &a)], &[ns("ns1", &ns1), ns("ns2", &ns2)]).await;
    assert_eq!(res.ns_disagree, ["MX"]);
    let f = code(&fs, "dns_authoritative_mismatch").expect("mismatch finding");
    assert_eq!(f.severity, Severity::Critical);
    assert!(f.message.contains("same serial") && f.message.contains("2024"), "{}", f.message);
    assert!(code(&fs, "dns_authoritative_behind").is_none());
}

#[tokio::test]
async fn nameservers_that_agree_on_data_are_fine_whatever_their_serials() {
    // Only the SOA differs: the data visitors get is the same, so nothing to report.
    let newer = zone("example").replace("2024 7200", "2030 7200");
    let (ns1, ns2) = (FakeDns::start(&newer).await.authoritative(), FakeDns::start(&zone("example")).await.authoritative());
    let a = FakeDns::start(&zone("example")).await;
    let (res, fs) = run(&[r("A", &a)], &[ns("ns1", &ns1), ns("ns2", &ns2)]).await;
    assert!(res.ns_disagree.is_empty(), "{:?}", res.ns_disagree);
    assert!(code(&fs, "dns_authoritative_behind").is_none() && code(&fs, "dns_authoritative_mismatch").is_none());
}

#[tokio::test]
async fn a_nameserver_that_does_not_answer_is_reported() {
    let (ns1, down) = (FakeDns::start(&zone("example")).await.authoritative(), FakeDns::silent().await);
    let a = FakeDns::start(&zone("example")).await;
    let (res, fs) = run(&[r("A", &a)], &[ns("ns1", &ns1), ns("ns2", &down)]).await;
    assert!(res.nameservers[1].error.is_some());
    let f = code(&fs, "dns_authoritative_unreachable").expect("unreachable finding");
    assert!(f.message.contains("ns2"));
}

#[tokio::test]
async fn an_answer_without_the_authoritative_flag_is_not_trusted() {
    // A forwarder, or a network that intercepts DNS, answers as if it were the nameserver.
    let hijacked = FakeDns::start(&zone("example")).await;
    let old = FakeDns::start(&zone("moved_mx")).await;
    let (res, fs) = run(&[r("Old", &old)], &[ns("ns1", &hijacked)]).await;
    assert_eq!(res.nameservers[0].authoritative, Some(false));
    assert_eq!(res.agreement, Agreement::Inconclusive, "one resolver and no trusted nameserver: nothing to compare");
    assert!(res.stale.is_empty(), "an interceptor's answer must not be treated as the truth");
    assert!(code(&fs, "dns_authoritative_not_authoritative").is_some(), "{fs:?}");
}

#[tokio::test]
async fn a_name_the_nameservers_deny_but_a_resolver_still_serves() {
    let ns1 = FakeDns::start(&zone("other")).await.authoritative(); // example.com is gone
    let cached = FakeDns::start(&zone("example")).await;
    let (res, _) = run(&[r("Cached", &cached)], &[ns("ns1", &ns1)]).await;
    assert_eq!(res.stale["existence"], ["Cached"], "{:?}", res.stale);
}

#[tokio::test]
async fn nameservers_alone_can_answer() {
    let ns1 = FakeDns::start(&zone("example")).await.authoritative();
    let down = FakeDns::silent().await;
    let (res, _) = run(&[r("Down", &down)], &[ns("ns1", &ns1)]).await;
    assert!(res.resolvers[0].error.is_some() && res.nameservers[0].error.is_none());
}

// Discovery

const RECURSIVE: &str = "example.com. 300 IN NS ns1.example.com.\nns1.example.com. 300 IN A 127.0.0.1\nwww.example.com. 300 IN CNAME example.com.\n";

#[tokio::test]
async fn finds_the_nameservers_of_a_domain() {
    let rec = FakeDns::start(RECURSIVE).await;
    let found = discover_nameservers(&[rec.addr], "example.com", 5353, T).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!((found[0].name.as_str(), found[0].address.to_string()), ("ns1.example.com", "127.0.0.1:5353".to_string()));
}

#[tokio::test]
async fn a_host_below_the_zone_apex_uses_the_zones_nameservers() {
    let rec = FakeDns::start(RECURSIVE).await;
    let found = discover_nameservers(&[rec.addr], "www.example.com", 5353, T).await.unwrap();
    assert_eq!(found[0].name, "ns1.example.com");
}

#[tokio::test]
async fn tries_the_next_resolver_when_one_is_down() {
    let (down, rec) = (FakeDns::silent().await, FakeDns::start(RECURSIVE).await);
    let found = discover_nameservers(&[down.addr, rec.addr], "example.com", 53, Duration::from_millis(200)).await.unwrap();
    assert_eq!(found.len(), 1);
}

#[tokio::test]
async fn a_domain_with_no_nameservers_is_an_error() {
    let rec = FakeDns::start(RECURSIVE).await;
    assert!(discover_nameservers(&[rec.addr], "nope.test", 53, T).await.is_err());
}

#[tokio::test]
async fn asks_one_address_per_family_for_each_nameserver() {
    // Anycast operators list several addresses per nameserver; one is enough to ask.
    let rec = FakeDns::start("example.com. 300 IN NS ns1.example.com.\nns1.example.com. 300 IN A 127.0.0.1\nns1.example.com. 300 IN A 127.0.0.2\nns1.example.com. 300 IN A 127.0.0.3\n").await;
    let found = discover_nameservers(&[rec.addr], "example.com", 53, T).await.unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].name, "ns1.example.com", "a lone address needs no suffix");
}

#[tokio::test]
async fn resolvers_that_all_serve_old_records_are_cached_not_propagated() {
    // The resolvers agree with each other, but not with the nameservers.
    let ns1 = FakeDns::start(&zone("moved_mx")).await.authoritative();
    let (a, b) = (FakeDns::start(&zone("example")).await, FakeDns::start(&zone("example")).await);
    let (res, fs) = run(&[r("A", &a), r("B", &b)], &[ns("ns1", &ns1)]).await;
    assert!(res.disagree.is_empty(), "the resolvers agree among themselves");
    assert_eq!(res.agreement, Agreement::Cached);
    assert!(code(&fs, "dns_propagation_consistent").is_none(), "must not claim Propagated: {fs:?}");
    assert!(code(&fs, "dns_propagation_stale_cache").is_some());
}

#[tokio::test]
async fn resolvers_that_disagree_with_no_trusted_nameserver_are_just_different() {
    let (a, b) = (FakeDns::start(&zone("moved_mx")).await, FakeDns::start(&zone("example")).await);
    let (res, _) = run(&[r("New", &a), r("Old", &b)], &[]).await;
    assert_eq!(res.agreement, Agreement::ResolversDiffer);
}

// A network that answers DNS itself looks like nameservers that answer without the
// authoritative flag and offer recursion. The default fake server does exactly that.

#[tokio::test]
async fn nameservers_that_all_answer_like_a_forwarder_mean_the_network_intercepts_dns() {
    let (ns1, ns2) = (FakeDns::start(&zone("example")).await, FakeDns::start(&zone("example")).await);
    let (a, b) = (FakeDns::start(&zone("example")).await, FakeDns::start(&zone("example")).await);
    let (res, fs) = run(&[r("A", &a), r("B", &b)], &[ns("ns1", &ns1), ns("ns2", &ns2)]).await;
    assert!(res.intercepted);
    assert_eq!(res.agreement, Agreement::Intercepted);
    let f = code(&fs, "dns_network_intercepts").expect("interception finding");
    assert_eq!(f.severity, Severity::Warning);
    assert!(f.message.contains("ns1") && f.message.contains("ns2"), "{}", f.message);
    assert!(code(&fs, "dns_authoritative_not_authoritative").is_none(), "one alarm, not two");
    assert!(code(&fs, "dns_propagation_consistent").is_none(), "must not call it Propagated when the resolvers are one box: {fs:?}");
}

#[tokio::test]
async fn one_odd_nameserver_is_not_a_whole_network() {
    let one = FakeDns::start(&zone("example")).await;
    let a = FakeDns::start(&zone("example")).await;
    let (res, fs) = run(&[r("A", &a)], &[ns("ns1", &one)]).await;
    assert!(!res.intercepted);
    assert!(code(&fs, "dns_authoritative_not_authoritative").is_some());
}

#[tokio::test]
async fn a_real_nameserver_among_them_rules_interception_out() {
    let (real, odd) = (FakeDns::start(&zone("example")).await.authoritative(), FakeDns::start(&zone("example")).await);
    let a = FakeDns::start(&zone("example")).await;
    let (res, _) = run(&[r("A", &a)], &[ns("ns1", &real), ns("ns2", &odd)]).await;
    assert!(!res.intercepted);
}

#[tokio::test]
async fn nameservers_that_are_not_authoritative_but_do_not_recurse_are_not_interception() {
    // Lame, not a forwarder: no recursion offered.
    let (n1, n2) = (FakeDns::start(&zone("example")).await.recursion_available(false), FakeDns::start(&zone("example")).await.recursion_available(false));
    let a = FakeDns::start(&zone("example")).await;
    let (res, _) = run(&[r("A", &a)], &[ns("ns1", &n1), ns("ns2", &n2)]).await;
    assert!(!res.intercepted);
}
