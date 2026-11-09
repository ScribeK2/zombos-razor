mod common;

use std::time::Duration;

use common::{FakeDns, zone};
use hickory_proto::rr::RecordType;
use zombo_core::email_auth::{
    Alignment, DKIM_COMMON_SELECTORS, DkimKeyError, EffectiveAll, EmailAuthResult, KeyType, Mechanism, NodeError, Policy, Qualifier, SpfAudit, SpfNode, email_auth,
};

const T: Duration = Duration::from_millis(500);

async fn run(zone_text: &str) -> EmailAuthResult {
    let s = FakeDns::start(zone_text).await;
    email_auth(s.addr, "example.com", &[], T).await
}

async fn spf(zone_text: &str) -> SpfAudit {
    run(zone_text).await.spf
}

fn errors(a: &SpfAudit) -> Vec<String> {
    a.errors.iter().map(ToString::to_string).collect()
}

fn depth(n: &SpfNode) -> usize {
    1 + n.terms.iter().filter_map(|t| t.target.as_deref()).map(depth).max().unwrap_or(0)
}

#[tokio::test]
async fn a_healthy_domains_spf_resolves_its_include() {
    let a = spf(&zone("email_healthy")).await;
    assert_eq!((a.all, a.lookups, a.void_lookups), (EffectiveAll::All(Qualifier::Fail), 1, 0));
    assert!(a.errors.is_empty() && a.failed.is_empty(), "{:?}", a);
    let tree = a.tree.expect("a tree");
    let inc = &tree.terms[0];
    assert_eq!(inc.mechanism, Mechanism::Include("_spf.provider.test".into()));
    let target = inc.target.as_deref().expect("the include is resolved");
    assert_eq!(target.record.as_deref(), Some("v=spf1 ip4:198.51.100.0/24 ~all"));
}

#[tokio::test]
async fn lookups_are_counted_through_includes() {
    // 2 at the top + 3 in one + 4 in two + 2 in three + 2 in four = 13.
    let a = spf(&zone("email_spf_lookups")).await;
    assert_eq!((a.lookups, a.void_lookups, a.all), (13, 0, EffectiveAll::All(Qualifier::Fail)));
    assert!(a.errors.is_empty() && !a.truncated, "{:?}", a);
}

#[tokio::test]
async fn permerrors_are_found_in_the_record_and_its_includes() {
    let a = spf(&zone("email_spf_permerrors")).await;
    let errs = errors(&a).join("\n");
    for want in ["gone.test has no SPF record", "loops back to example.com", r#"bad address "ip4:300.1.1.1""#, r#"unknown mechanism "bogus""#] {
        assert!(errs.contains(want), "errors missing {want:?}: {errs}");
    }
    assert_eq!(a.all, EffectiveAll::All(Qualifier::SoftFail));
    // gone.test has no TXT records at all, so it is a void lookup too.
    assert_eq!(a.void_lookups, 1);
}

#[tokio::test]
async fn nothing_found_is_a_void_lookup_and_three_is_too_many() {
    let a = spf(&zone("email_spf_voids")).await;
    assert_eq!(a.void_lookups, 3);
    assert!(errors(&a).contains(&"3 void lookups (limit 2)".to_string()), "{:?}", errors(&a));
    let tree = a.tree.unwrap();
    assert_eq!(tree.terms.iter().filter(|t| t.void).count(), 3);
}

#[tokio::test]
async fn two_voids_are_within_the_limit() {
    let a = spf("example.com. 300 IN TXT \"v=spf1 a:nx1.test mx:nx2.test -all\"\n").await;
    assert_eq!(a.void_lookups, 2);
    assert!(a.errors.is_empty());
}

#[tokio::test]
async fn an_a_term_that_has_only_aaaa_is_not_void() {
    let a = spf("example.com. 300 IN TXT \"v=spf1 a:h.test -all\"\nh.test. 300 IN AAAA 2001:db8::1\n").await;
    assert_eq!(a.void_lookups, 0);
}

#[tokio::test]
async fn an_include_with_txt_but_no_spf_is_an_error_not_a_void() {
    let a = spf("example.com. 300 IN TXT \"v=spf1 include:t.test -all\"\nt.test. 300 IN TXT \"hello\"\n").await;
    assert_eq!(a.void_lookups, 0);
    assert_eq!(errors(&a), ["include target t.test has no SPF record"]);
    assert_eq!(a.tree.unwrap().terms[0].target.as_deref().unwrap().error, Some(NodeError::NoRecord));
}

#[tokio::test]
async fn an_include_with_two_spf_records_is_an_error() {
    let a = spf("example.com. 300 IN TXT \"v=spf1 include:t.test -all\"\nt.test. 300 IN TXT \"v=spf1 -all\"\nt.test. 300 IN TXT \"v=spf1 ~all\"\n").await;
    assert_eq!(errors(&a), ["include target t.test has 2 SPF records"]);
}

#[tokio::test]
async fn the_effective_all_follows_the_rfc() {
    for (rec, want) in [
        ("v=spf1 +all", EffectiveAll::All(Qualifier::Pass)),
        ("v=spf1 all", EffectiveAll::All(Qualifier::Pass)),
        ("v=spf1 ?all", EffectiveAll::All(Qualifier::Neutral)),
        ("v=spf1 ip4:192.0.2.1", EffectiveAll::Absent),
        ("v=spf1 ~all", EffectiveAll::All(Qualifier::SoftFail)),
        ("v=spf1 redirect=_spf.provider.test", EffectiveAll::All(Qualifier::SoftFail)), // the redirect's all applies
        ("V=SPF1 ip4:192.0.2.1 -ALL", EffectiveAll::All(Qualifier::Fail)),
        ("v=spf1 -all redirect=nowhere.invalid", EffectiveAll::All(Qualifier::Fail)), // redirect ignored next to all
    ] {
        let a = spf(&format!("example.com. 300 IN TXT \"{rec}\"\n{}", zone("email_spf_all_base"))).await;
        assert_eq!(a.all, want, "{rec}");
        assert!(a.errors.is_empty(), "{rec}: {:?}", errors(&a));
    }
}

#[tokio::test]
async fn a_redirect_next_to_all_costs_no_lookup() {
    let a = spf("example.com. 300 IN TXT \"v=spf1 -all redirect=nowhere.invalid\"\n").await;
    assert_eq!((a.lookups, a.void_lookups), (0, 0));
    assert!(a.tree.unwrap().terms.iter().all(|t| t.target.is_none()));
}

#[tokio::test]
async fn a_macro_is_counted_but_not_resolved() {
    let a = spf(&zone("email_spf_macro_redirect")).await;
    assert_eq!((a.lookups, a.void_lookups), (1, 0));
    assert_eq!(a.all, EffectiveAll::Unknown);
    assert!(a.errors.is_empty() && a.failed.is_empty());
}

#[tokio::test]
async fn two_spf_records_stop_the_walk() {
    let a = spf(&zone("email_spf_multiple")).await;
    assert_eq!(a.records.len(), 2);
    assert!(a.tree.is_none());
    assert_eq!(a.lookups, 0);
}

#[tokio::test]
async fn no_spf_record_is_not_an_error() {
    let a = spf(&zone("email_missing")).await;
    assert!(a.records.is_empty() && a.tree.is_none() && a.lookup_error.is_none());
}

#[tokio::test]
async fn a_diamond_include_is_legal_and_counted_each_time() {
    let a = spf("example.com. 60 IN TXT \"v=spf1 include:l.test include:r.test -all\"\nl.test. 60 IN TXT \"v=spf1 include:d.test\"\nr.test. 60 IN TXT \"v=spf1 include:d.test\"\nd.test. 60 IN TXT \"v=spf1 ip4:192.0.2.1\"\n").await;
    assert_eq!(a.lookups, 4);
    assert!(a.errors.is_empty(), "{:?}", errors(&a));
}

#[tokio::test]
async fn a_loop_through_a_redirect_is_named_as_one() {
    let a = spf("example.com. 60 IN TXT \"v=spf1 redirect=a.test\"\na.test. 60 IN TXT \"v=spf1 redirect=example.com\"\n").await;
    assert_eq!(errors(&a), ["redirect loops back to example.com"]);
    assert_eq!(a.all, EffectiveAll::Unknown);
}

#[tokio::test]
async fn a_chain_of_a_hundred_includes_stops_at_the_cap() {
    let zone: String = (0..100).map(|i| format!("c{i}.test. 60 IN TXT \"v=spf1 include:c{}.test\"\n", i + 1)).collect::<String>() + "example.com. 60 IN TXT \"v=spf1 include:c0.test\"\n";
    let a = spf(&zone).await;
    assert!(a.truncated);
    assert!(a.lookups > 30);
    assert!(depth(a.tree.as_ref().unwrap()) <= 31, "depth {}", depth(a.tree.as_ref().unwrap()));
}

#[tokio::test]
async fn a_huge_record_of_includes_is_walked_within_the_caps() {
    // 160 strings of 255 bytes: about 40 KB of `include:` terms, each a lookup.
    let strings: String = (0..160).map(|_| format!("\"{}\" ", "include:s.test ".repeat(17))).collect();
    let a = spf(&format!("example.com. 60 IN TXT \"v=spf1 \" {strings}\ns.test. 60 IN TXT \"v=spf1 -all\"\n")).await;
    assert!(a.truncated);
    assert!(a.lookups <= 600, "{}", a.lookups);
    assert!(a.errors.iter().any(|e| e.to_string().contains("more than 512 terms")));
}

#[tokio::test]
async fn a_self_include_is_a_loop_not_a_hang() {
    let a = spf("example.com. 60 IN TXT \"v=spf1 include:example.com include:EXAMPLE.com.\"\n").await;
    assert_eq!(errors(&a), ["include loops back to example.com", "include loops back to example.com"]);
}

#[tokio::test]
async fn the_walk_is_deterministic_although_lookups_run_concurrently() {
    let z = zone("email_spf_lookups");
    let s = FakeDns::start(&z).await;
    let first = email_auth(s.addr, "example.com", &[], T).await.spf;
    for _ in 0..5 {
        let again = email_auth(s.addr, "example.com", &[], T).await.spf;
        assert_eq!(serde_json::to_string(&first).unwrap(), serde_json::to_string(&again).unwrap());
    }
}

#[tokio::test]
async fn a_refused_txt_lookup_is_a_failed_lookup_for_the_domain() {
    let s = FakeDns::start("example.com. 60 IN TXT \"v=spf1 -all\"\n").await.refuse(RecordType::TXT);
    let a = email_auth(s.addr, "example.com", &[], T).await.spf;
    assert!(a.lookup_error.as_deref().is_some_and(|e| e.contains("Refused")), "{:?}", a.lookup_error);
    assert!(a.tree.is_none());
}

#[tokio::test]
async fn a_failed_nested_lookup_is_listed_in_failed() {
    let s = FakeDns::start("example.com. 60 IN TXT \"v=spf1 a:h.test include:i.test -all\"\ni.test. 60 IN TXT \"v=spf1 -all\"\n").await.refuse(RecordType::A);
    let a = email_auth(s.addr, "example.com", &[], T).await.spf;
    assert_eq!(a.failed.len(), 1, "{:?}", a.failed);
    assert!(a.failed[0].starts_with("a:h.test: "), "{:?}", a.failed);
    assert_eq!(a.void_lookups, 0);
}

#[tokio::test]
async fn a_silent_resolver_fails_the_lookup() {
    let s = FakeDns::silent().await;
    let a = email_auth(s.addr, "example.com", &[], Duration::from_millis(200)).await.spf;
    assert!(a.lookup_error.is_some() && a.tree.is_none());
}

fn sel(names: &[&str]) -> Vec<String> {
    names.iter().map(ToString::to_string).collect()
}

#[tokio::test]
async fn a_healthy_domain_has_one_dkim_key_behind_a_cname() {
    let r = run(&zone("email_healthy")).await;
    let k = &r.dkim.keys;
    assert_eq!(k.len(), 1, "{k:?}");
    assert_eq!((k[0].selector.as_str(), k[0].bits, k[0].key_type.clone()), ("selector1", Some(2048), KeyType::Rsa));
    assert_eq!(k[0].cname.as_deref(), Some("selector1-example._domainkey.provider.test"));
    assert!(r.dkim.failed.is_empty());
    let d = r.dmarc.parsed.expect("a DMARC record");
    assert_eq!((d.policy, d.subdomain_policy, d.pct, d.adkim, d.aspf), (Some(Policy::Reject), Some(Policy::Quarantine), 100, Alignment::Strict, Alignment::Relaxed));
    assert_eq!(d.rua, ["mailto:dmarc@example.com"]);
}

#[tokio::test]
async fn a_domain_with_no_mail_records_has_none_of_them() {
    let r = run(&zone("email_missing")).await;
    assert!(r.spf.records.is_empty() && r.dkim.keys.is_empty() && r.dmarc.records.is_empty() && r.dmarc.parsed.is_none());
    assert!(r.dkim.checked.contains(&"google".to_string()));
    assert_eq!(r.dkim.checked.len(), DKIM_COMMON_SELECTORS.len());
    assert!(r.answered());
}

#[tokio::test]
async fn dkim_key_sizes_revoked_and_broken_keys_are_told_apart() {
    let r = run(&zone("email_dkim_strength")).await;
    let by = |s: &str| r.dkim.keys.iter().find(|k| k.selector == s).unwrap_or_else(|| panic!("no key for {s}"));
    assert_eq!(r.dkim.keys.len(), 6, "s2 is not a DKIM record: {:?}", r.dkim.keys);
    assert_eq!((by("google").bits, by("k1").bits, by("dkim").bits), (Some(512), Some(1024), None));
    assert!(by("s1").revoked && !by("google").revoked);
    assert_eq!(by("dkim").error, Some(DkimKeyError::NotBase64));
}

#[tokio::test]
async fn custom_selectors_are_checked_only_when_asked() {
    let z = zone("email_dkim_custom");
    let s = FakeDns::start(&z).await;
    let plain = email_auth(s.addr, "example.com", &[], T).await.dkim;
    assert!(plain.keys.is_empty() && !plain.checked.contains(&"acme2024".to_string()));

    let asked = email_auth(s.addr, "example.com", &sel(&["Acme2024", "other", "google", "other"]), T).await.dkim;
    assert_eq!(asked.custom, ["acme2024", "other", "google"]);
    assert!(asked.checked.contains(&"acme2024".into()) && asked.checked.contains(&"other".into()));
    assert_eq!(asked.checked.iter().filter(|c| *c == "google").count(), 1);
    assert_eq!(asked.keys.len(), 1);
    assert_eq!(asked.keys[0].selector, "acme2024");
}

#[tokio::test]
async fn an_unusable_selector_is_a_failed_lookup_not_a_crash() {
    let long = "x".repeat(200);
    let r = email_auth(FakeDns::start("").await.addr, "example.com", &sel(&["bad..name", &long]), T).await;
    assert_eq!(r.dkim.failed, ["bad..name", long.as_str()]);
}

#[tokio::test]
async fn at_most_twenty_custom_selectors_are_queried() {
    let many: Vec<String> = (0..50).map(|i| format!("c{i}")).collect();
    let r = email_auth(FakeDns::start("").await.addr, "example.com", &many, T).await;
    assert_eq!(r.dkim.custom.len(), 20);
    assert_eq!(r.dkim.checked.len(), DKIM_COMMON_SELECTORS.len() + 20);
}

#[tokio::test]
async fn dmarc_monitoring_record_is_read() {
    let d = run(&zone("email_dmarc_monitoring")).await.dmarc.parsed.unwrap();
    assert_eq!((d.policy, d.pct, d.aspf), (Some(Policy::None), 50, Alignment::Strict));
    assert!(d.rua.is_empty());
}

#[tokio::test]
async fn two_dmarc_records_are_listed_but_not_read() {
    let r = run("_dmarc.example.com. 60 IN TXT \"v=DMARC1; p=none\"\n_dmarc.example.com. 60 IN TXT \"v=DMARC1; p=reject\"\n_dmarc.example.com. 60 IN TXT \"other\"\n").await;
    assert_eq!(r.dmarc.records.len(), 2);
    assert!(r.dmarc.parsed.is_none());
}

#[tokio::test]
async fn a_silent_resolver_leaves_nothing_answered() {
    let s = FakeDns::silent().await;
    let r = email_auth(s.addr, "example.com", &[], Duration::from_millis(200)).await;
    assert!(!r.answered());
    assert!(r.spf.lookup_error.is_some() && r.dmarc.lookup_error.is_some());
    assert_eq!(r.dkim.failed, r.dkim.checked);
}

#[tokio::test]
async fn a_refused_mx_query_does_not_fail_the_audit() {
    let s = FakeDns::start("_dmarc.example.com. 60 IN TXT \"v=DMARC1; p=none\"\n").await.refuse(RecordType::MX);
    assert!(email_auth(s.addr, "example.com", &[], T).await.answered());
}
