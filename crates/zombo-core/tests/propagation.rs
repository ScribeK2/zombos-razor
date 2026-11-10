#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod common;

use common::{FakeDns, zone};
use std::time::Duration;
use zombo_core::propagation::{Agreement, Scope, Vantage, propagation, propagation_findings};

fn resolver(name: &str, s: &FakeDns) -> Vantage {
    Vantage::resolver(name, "Test", s.addr)
}

fn codes(fs: &[zombo_core::Finding]) -> Vec<&str> {
    fs.iter().map(|f| f.code).collect()
}

#[tokio::test]
async fn agrees_when_every_resolver_matches() {
    let (a, b) = (FakeDns::start(&zone("example")).await, FakeDns::start(&zone("example")).await);
    let res =
        propagation(&[resolver("One", &a), resolver("Two", &b)], "example.com", Scope::All, Duration::from_millis(500))
            .await
            .unwrap();
    assert_eq!(res.resolvers.len(), 2);
    assert!(res.disagree.is_empty(), "{:?}", res.disagree);
    assert_eq!(res.resolvers[0].answers["MX"], ["10 mail.example.com."]);
    assert!(codes(&propagation_findings("example.com", &res)).contains(&"dns_propagation_consistent"));
    assert_eq!(res.agreement, Agreement::Agree);
}

use hickory_proto::rr::RecordType;
use zombo_core::propagation::PropagationError;

const T: Duration = Duration::from_millis(500);

#[tokio::test]
async fn flags_resolvers_that_disagree() {
    let (a, b) = (FakeDns::start(&zone("moved_mx")).await, FakeDns::start(&zone("moved_mx")).await);
    let (stale, down) = (FakeDns::start(&zone("example")).await, FakeDns::silent().await);
    let res = propagation(
        &[resolver("Updated", &a), resolver("Also updated", &b), resolver("Stale", &stale), resolver("Down", &down)],
        "example.com",
        Scope::All,
        Duration::from_millis(300),
    )
    .await
    .unwrap();
    assert!(res.disagree.contains(&"MX".into()) && !res.disagree.contains(&"NS".into()), "{:?}", res.disagree);
    assert_eq!(res.agreement, Agreement::ResolversDiffer);
    assert!(res.resolvers[3].error.is_some(), "{:?}", res.resolvers[3]);
    let fs = propagation_findings("example.com", &res);
    let mismatch = fs.iter().find(|f| f.code == "dns_propagation_mismatch").expect("mismatch finding");
    assert_eq!(mismatch.severity, zombo_core::Severity::Warning);
    assert!(codes(&fs).contains(&"dns_propagation_unreachable"));
}

#[tokio::test]
async fn differing_addresses_are_info_not_a_warning() {
    // CDNs and geo-DNS legitimately answer A/AAAA differently per region.
    let (us, eu) = (FakeDns::start(&zone("example")).await, FakeDns::start(&zone("geo_eu")).await);
    let res = propagation(&[resolver("US", &us), resolver("EU", &eu)], "example.com", Scope::All, T).await.unwrap();
    let fs = propagation_findings("example.com", &res);
    assert!(!codes(&fs).contains(&"dns_propagation_mismatch"), "{:?}", codes(&fs));
    assert!(codes(&fs).contains(&"dns_propagation_addresses_vary"), "{:?}", codes(&fs));
}

#[tokio::test]
async fn a_failed_query_on_one_resolver_is_not_a_disagreement() {
    let one = FakeDns::start(&zone("example")).await;
    let refused = FakeDns::start(&zone("example")).await.refuse(RecordType::TXT);
    let res = propagation(&[resolver("One", &one), resolver("TXT refused", &refused)], "example.com", Scope::All, T)
        .await
        .unwrap();
    assert!(!res.disagree.contains(&"TXT".into()), "{:?}", res.disagree);
    assert_eq!(res.resolvers[1].failed, ["TXT"]);
    assert!(!codes(&propagation_findings("example.com", &res)).contains(&"dns_propagation_mismatch"));
}

#[tokio::test]
async fn too_few_answers_cannot_be_called_propagated() {
    let (one, down) = (FakeDns::start(&zone("example")).await, FakeDns::silent().await);
    let res = propagation(
        &[resolver("One", &one), resolver("Down", &down)],
        "example.com",
        Scope::All,
        Duration::from_millis(300),
    )
    .await
    .unwrap();
    let fs = propagation_findings("example.com", &res);
    let c = codes(&fs);
    assert!(!c.contains(&"dns_propagation_consistent") && c.contains(&"dns_propagation_insufficient"), "{c:?}");
    assert_eq!(res.agreement, Agreement::Inconclusive);
}

#[tokio::test]
async fn no_resolver_answering_is_an_error() {
    let down = FakeDns::silent().await;
    let err = propagation(&[resolver("Down", &down)], "example.com", Scope::All, Duration::from_millis(300))
        .await
        .unwrap_err();
    assert!(matches!(err, PropagationError::NoneAnswered));
}

#[tokio::test]
async fn a_name_that_exists_nowhere_is_not_propagated() {
    let (a, b) = (FakeDns::start(&zone("example")).await, FakeDns::start(&zone("example")).await);
    let res = propagation(&[resolver("One", &a), resolver("Two", &b)], "nope.test", Scope::All, T).await.unwrap();
    let fs = propagation_findings("nope.test", &res);
    let c = codes(&fs);
    assert!(!c.contains(&"dns_propagation_consistent") && c.contains(&"dns_propagation_nxdomain"), "{c:?}");
}

#[tokio::test]
async fn existence_differing_between_resolvers_is_a_mismatch() {
    let (new, old) = (FakeDns::start(&zone("example")).await, FakeDns::start(&zone("other")).await);
    let res = propagation(&[resolver("New", &new), resolver("Old", &old)], "example.com", Scope::All, T).await.unwrap();
    assert!(res.disagree.contains(&"existence".into()), "{:?}", res.disagree);
    assert!(codes(&propagation_findings("example.com", &res)).contains(&"dns_propagation_mismatch"));
}

#[tokio::test]
async fn scope_limits_the_compared_types() {
    // MX differs, but the web scope does not look at MX.
    let (a, b) = (FakeDns::start(&zone("moved_mx")).await, FakeDns::start(&zone("example")).await);
    let rs = [resolver("New", &a), resolver("Stale", &b)];
    let web = propagation(&rs, "example.com", Scope::Web, T).await.unwrap();
    assert_eq!(web.types, ["A", "AAAA", "CNAME"]);
    assert!(web.disagree.is_empty(), "{:?}", web.disagree);
    let mail = propagation(&rs, "example.com", Scope::Mail, T).await.unwrap();
    assert_eq!(mail.disagree, ["MX"]);
}

// New in Rust (Go discards TTLs and only reports at the end).

#[tokio::test]
async fn reports_the_ttl_each_resolver_returned() {
    let a = FakeDns::start(&zone("example")).await;
    let res = propagation(&[resolver("One", &a)], "example.com", Scope::All, T).await.unwrap();
    assert_eq!(res.resolvers[0].ttl["MX"], 300);
}

#[tokio::test]
async fn reports_each_resolver_as_it_answers() {
    let (a, down) = (FakeDns::start(&zone("example")).await, FakeDns::silent().await);
    let mut seen = vec![];
    propagation_with(
        &[resolver("Down", &down), resolver("Fast", &a)],
        &[],
        "example.com",
        Scope::Web,
        Duration::from_millis(400),
        |r| seen.push(r.vantage.name.clone()),
    )
    .await
    .unwrap();
    assert_eq!(seen, ["Fast", "Down"], "the fast resolver is reported before the one that times out");
}

use zombo_core::propagation::propagation_with;

#[test]
fn every_built_in_resolver_address_parses() {
    // The tables drop an entry that fails to parse, so a typo would silently remove a vantage.
    assert_eq!(zombo_core::propagation::default_resolvers().len(), 10);
    assert_eq!(zombo_core::dnssec::validating_resolvers().len(), 4);
}
