#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod common;

use std::{collections::BTreeSet, net::IpAddr, time::Duration};

use common::FakeDns;
use zombo_core::{
    Finding, Severity,
    delegation::{DelegatedServer, DelegationResult, Ports, ServerState, check_delegation, delegation_findings},
};

fn code<'a>(fs: &'a [Finding], c: &str) -> Option<&'a Finding> {
    fs.iter().find(|f| f.code == c)
}
fn codes(fs: &[Finding]) -> Vec<&str> {
    fs.iter().map(|f| f.code).collect()
}
fn set<T: Ord>(v: impl IntoIterator<Item = T>) -> BTreeSet<T> {
    v.into_iter().collect()
}
fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

// A healthy delegation, to break one thing at a time.
fn healthy() -> DelegationResult {
    let ns = ["ns1.example.com", "ns2.example.com"];
    DelegationResult {
        apex: "example.com".into(),
        parent: "com".into(),
        parent_ns: set(ns.map(String::from)),
        glue: ns.iter().enumerate().map(|(i, n)| (n.to_string(), set([ip(&format!("192.0.2.{}", i + 1))]))).collect(),
        servers: ns
            .iter()
            .map(|n| DelegatedServer {
                name: n.to_string(),
                address: None,
                state: ServerState::Ok { serial: 1 },
                child_ns: Some(set(ns.map(String::from))),
            })
            .collect(),
        glue_served: ns
            .iter()
            .enumerate()
            .map(|(i, n)| (n.to_string(), set([ip(&format!("192.0.2.{}", i + 1))])))
            .collect(),
        unresolvable: vec![],
        cnames: vec![],
    }
}

#[test]
fn a_healthy_delegation_says_so() {
    let fs = delegation_findings(&healthy());
    assert_eq!(codes(&fs), ["dns_delegation_ok"]);
    assert_eq!(fs[0].severity, Severity::Ok);
}

#[test]
fn a_single_nameserver_is_a_warning() {
    let mut r = healthy();
    r.parent_ns = set(["ns1.example.com".to_string()]);
    r.servers.truncate(1);
    r.servers[0].child_ns = Some(r.parent_ns.clone());
    let fs = delegation_findings(&r);
    assert_eq!(code(&fs, "dns_delegation_single_ns").unwrap().severity, Severity::Warning);
    assert!(code(&fs, "dns_delegation_ok").is_none());
}

#[test]
fn a_server_that_does_not_answer_is_unreachable() {
    let mut r = healthy();
    r.servers[1].state = ServerState::Unreachable;
    r.servers[1].child_ns = None;
    let f = delegation_findings(&r);
    let f = code(&f, "dns_delegation_unreachable").expect("unreachable");
    assert!(f.message.contains("ns2.example.com") && !f.message.contains("ns1.example.com"), "{}", f.message);
}

#[test]
fn a_server_that_answers_but_does_not_serve_the_zone_is_lame() {
    let mut r = healthy();
    r.servers[0].state = ServerState::Lame { why: "REFUSED (authoritative flag not set)".into(), recursive: false };
    r.servers[0].child_ns = None;
    let fs = delegation_findings(&r);
    let f = code(&fs, "dns_delegation_lame").expect("lame");
    assert_eq!(f.severity, Severity::Critical);
    assert!(f.message.contains("ns1.example.com") && f.message.contains("REFUSED"), "{}", f.message);
}

#[test]
fn parent_and_zone_disagreeing_about_nameservers_is_reported_both_ways() {
    let mut r = healthy();
    r.parent_ns = set(["ns1.example.com", "old.example.net"].map(String::from));
    for s in &mut r.servers {
        s.child_ns = Some(set(["ns1.example.com", "new.example.net"].map(String::from)));
    }
    let fs = delegation_findings(&r);
    let f = code(&fs, "dns_delegation_mismatch").expect("mismatch");
    assert!(f.message.contains("old.example.net only at the parent"), "{}", f.message);
    assert!(f.message.contains("new.example.net only in the zone"), "{}", f.message);
}

#[test]
fn an_in_zone_nameserver_without_glue_is_critical() {
    let mut r = healthy();
    r.glue.remove("ns2.example.com");
    let fs = delegation_findings(&r);
    let f = code(&fs, "dns_glue_missing").expect("missing glue");
    assert_eq!(f.severity, Severity::Critical);
    assert!(f.message.contains("ns2.example.com") && !f.message.contains("ns1.example.com"), "{}", f.message);
}

#[test]
fn an_out_of_zone_nameserver_needs_no_glue() {
    let mut r = healthy();
    r.parent_ns = set(["ns1.hoster.net", "ns2.hoster.net"].map(String::from));
    r.glue.clear();
    r.glue_served.clear();
    for s in &mut r.servers {
        s.child_ns = Some(r.parent_ns.clone());
    }
    assert_eq!(codes(&delegation_findings(&r)), ["dns_delegation_ok"]);
}

#[test]
fn glue_that_differs_from_the_zone_is_critical() {
    let mut r = healthy();
    r.glue_served.insert("ns1.example.com".into(), set([ip("198.51.100.7")]));
    let fs = delegation_findings(&r);
    let f = code(&fs, "dns_glue_mismatch").expect("glue mismatch");
    assert!(f.message.contains("192.0.2.1") && f.message.contains("198.51.100.7"), "{}", f.message);
}

#[test]
fn glue_without_an_ipv6_address_is_not_a_break() {
    // The zone has AAAA for the nameserver; the parent only has the A. Fine.
    let mut r = healthy();
    r.glue_served.insert("ns1.example.com".into(), set([ip("192.0.2.1"), ip("2001:db8::1")]));
    assert_eq!(codes(&delegation_findings(&r)), ["dns_delegation_ok"]);
}

#[test]
fn an_unresolvable_nameserver_name_is_critical() {
    let mut r = healthy();
    r.unresolvable = vec!["ns2.example.com".into()];
    assert!(code(&delegation_findings(&r), "dns_ns_unresolvable").is_some());
}

#[test]
fn a_nameserver_that_is_a_cname_is_critical() {
    let mut r = healthy();
    r.cnames = vec!["ns1.example.com".into()];
    assert_eq!(code(&delegation_findings(&r), "dns_ns_is_cname").unwrap().severity, Severity::Critical);
}

#[test]
fn servers_that_all_answer_like_a_forwarder_mean_the_network_intercepts_dns() {
    let mut r = healthy();
    for (i, s) in r.servers.iter_mut().enumerate() {
        s.address = Some(format!("192.0.2.{}:53", i + 1).parse().unwrap());
        s.state = ServerState::Lame { why: "No Error (authoritative flag not set)".into(), recursive: true };
        s.child_ns = None;
    }
    let fs = delegation_findings(&r);
    let f = code(&fs, "dns_network_intercepts").expect("interception finding");
    assert_eq!(f.severity, Severity::Warning);
    assert!(code(&fs, "dns_delegation_lame").is_none(), "one alarm, not two: {fs:?}");
}

#[test]
fn one_lame_server_that_recurses_is_just_lame() {
    let mut r = healthy();
    r.servers[0].address = Some("192.0.2.1:53".parse().unwrap());
    r.servers[0].state = ServerState::Lame { why: "No Error (authoritative flag not set)".into(), recursive: true };
    r.servers[0].child_ns = None;
    let fs = delegation_findings(&r);
    assert!(code(&fs, "dns_delegation_lame").is_some() && code(&fs, "dns_network_intercepts").is_none(), "{fs:?}");
}

// The IO: ask a parent for the referral, then each delegated nameserver.

const T: Duration = Duration::from_millis(500);

struct Net {
    rec: FakeDns,
    ports: Ports,
    _keep: Vec<FakeDns>,
}

/// A recursive resolver that knows `com` and `example.com`, a parent that returns
/// `parent_zone` as a referral, and a child serving `child_zone`.
async fn net(parent_zone: &str, child_zone: Option<&str>) -> Net {
    let parent = FakeDns::start(parent_zone).await.referral();
    let child = match child_zone {
        Some(z) => FakeDns::start(z).await.authoritative(),
        None => FakeDns::silent().await,
    };
    let rec = FakeDns::start(
        "com. 300 IN NS a.gtld.test.\na.gtld.test. 300 IN A 127.0.0.1\nexample.com. 300 IN NS ns1.example.com.\nexample.com. 300 IN NS ns2.example.com.\nns1.example.com. 300 IN A 127.0.0.1\nns2.example.com. 300 IN A 127.0.0.1\n",
    )
    .await;
    Net { rec, ports: Ports { parent: parent.addr.port(), nameserver: child.addr.port() }, _keep: vec![parent, child] }
}

const PARENT: &str = "example.com. 300 IN NS ns1.example.com.\nexample.com. 300 IN NS ns2.example.com.\nns1.example.com. 300 IN A 127.0.0.1\nns2.example.com. 300 IN A 127.0.0.1\n";
const CHILD: &str = "example.com. 300 IN SOA ns1.example.com. h.example.com. 7 7200 3600 1209600 3600\nexample.com. 300 IN NS ns1.example.com.\nexample.com. 300 IN NS ns2.example.com.\nns1.example.com. 300 IN A 127.0.0.1\nns2.example.com. 300 IN A 127.0.0.1\n";

async fn run(n: &Net) -> (DelegationResult, Vec<Finding>) {
    let r = check_delegation(&[n.rec.addr], "example.com", n.ports, T).await.unwrap();
    let fs = delegation_findings(&r);
    (r, fs)
}

#[tokio::test]
async fn reads_the_delegation_from_the_parent_and_checks_each_server() {
    let n = net(PARENT, Some(CHILD)).await;
    let (r, fs) = run(&n).await;
    assert_eq!((r.apex.as_str(), r.parent.as_str()), ("example.com", "com"));
    assert_eq!(r.parent_ns, set(["ns1.example.com", "ns2.example.com"].map(String::from)));
    assert_eq!(r.glue["ns1.example.com"], set([ip("127.0.0.1")]));
    assert!(r.servers.iter().all(|s| s.state == ServerState::Ok { serial: 7 }), "{:?}", r.servers);
    assert_eq!(codes(&fs), ["dns_delegation_ok"], "{fs:?}");
}

#[tokio::test]
async fn finds_glue_that_differs_from_what_the_zone_serves() {
    let parent = PARENT.replace("ns1.example.com. 300 IN A 127.0.0.1", "ns1.example.com. 300 IN A 127.0.0.9");
    let n = net(&parent, Some(CHILD)).await;
    let (_, fs) = run(&n).await;
    assert!(code(&fs, "dns_glue_mismatch").is_some(), "{fs:?}");
}

#[tokio::test]
async fn finds_missing_glue() {
    let parent = "example.com. 300 IN NS ns1.example.com.\nexample.com. 300 IN NS ns2.example.com.\n";
    let n = net(parent, Some(CHILD)).await;
    let (_, fs) = run(&n).await;
    assert!(code(&fs, "dns_glue_missing").is_some(), "{fs:?}");
}

#[tokio::test]
async fn finds_a_zone_that_lists_a_nameserver_the_parent_does_not() {
    let child = format!("{CHILD}example.com. 300 IN NS ns3.example.com.\n");
    let n = net(PARENT, Some(&child)).await;
    let (_, fs) = run(&n).await;
    let f = code(&fs, "dns_delegation_mismatch").expect("mismatch");
    assert!(f.message.contains("ns3.example.com only in the zone"), "{}", f.message);
}

#[tokio::test]
async fn a_server_that_is_not_authoritative_for_the_zone_is_lame() {
    // Answers the SOA, but without the authoritative flag.
    let parent = FakeDns::start(PARENT).await.referral();
    let child = FakeDns::start(CHILD).await;
    let rec = FakeDns::start("com. 300 IN NS a.gtld.test.\na.gtld.test. 300 IN A 127.0.0.1\nexample.com. 300 IN NS ns1.example.com.\nns1.example.com. 300 IN A 127.0.0.1\n").await;
    let ports = Ports { parent: parent.addr.port(), nameserver: child.addr.port() };
    let r = check_delegation(&[rec.addr], "example.com", ports, T).await.unwrap();
    assert!(code(&delegation_findings(&r), "dns_delegation_lame").is_some());
}

#[tokio::test]
async fn a_silent_server_is_unreachable() {
    let n = net(PARENT, None).await;
    let r = check_delegation(&[n.rec.addr], "example.com", n.ports, Duration::from_millis(200)).await.unwrap();
    assert!(code(&delegation_findings(&r), "dns_delegation_unreachable").is_some());
}

#[tokio::test]
async fn a_top_level_name_has_no_parent_to_compare() {
    let n = net(PARENT, Some(CHILD)).await;
    let err = check_delegation(&[n.rec.addr], "com", n.ports, T).await.unwrap_err();
    assert!(err.to_string().contains("no parent zone"), "{err}");
}
