//! CAA lookup and OCSP stapling detection, against scripted DNS and local TLS servers.

#[path = "common/scripted.rs"]
mod scripted;
#[path = "common/stapling.rs"]
mod stapling;
#[path = "common/tls.rs"]
mod pki;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use hickory_proto::rr::{
    Name, RData, Record, RecordType,
    rdata::CAA,
};
use pki::{Ca, NOW};
use scripted::Reply;
use zombo_core::{
    Finding, Severity,
    tls::{TlsResult, check_tls_via},
    tls_extras::{CaaResult, caa_findings, check_caa, ocsp_findings},
};

const HOST: &str = "www.example.test";
const WAIT: Duration = Duration::from_secs(5);

fn caa(owner: &str, tag: &str, value: &str) -> Record {
    let mut data = CAA::new_issue(false, None, vec![]);
    data.tag = tag.into();
    data.value = value.as_bytes().to_vec();
    Record::from_rdata(Name::from_ascii(owner).unwrap(), 300, RData::CAA(data))
}

/// A zone with `sets` of (owner, tag, value); names not listed answer with no data.
async fn dns(sets: Vec<(&'static str, &'static str, &'static str)>) -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
    let asked = Arc::new(Mutex::new(vec![]));
    let log = asked.clone();
    let addr = scripted::serve(move |name, t| {
        assert_eq!(t, RecordType::CAA);
        log.lock().unwrap().push(name.to_string());
        let records: Vec<Record> = sets.iter().filter(|(o, _, _)| *o == name).map(|(o, tag, v)| caa(o, tag, v)).collect();
        Reply::Answers(records)
    })
    .await;
    (addr, asked)
}

fn codes(fs: &[Finding]) -> Vec<&'static str> {
    fs.iter().map(|f| f.code).collect()
}

async fn caa_of(sets: Vec<(&'static str, &'static str, &'static str)>) -> CaaResult {
    let (addr, _) = dns(sets).await;
    check_caa(&[addr], HOST, Duration::from_secs(2)).await
}

async fn served_by(ca: &Ca, sans: &[&str]) -> TlsResult {
    let leaf = ca.valid_leaf(sans);
    let addr = pki::serve(vec![leaf.der], leaf.key).await;
    check_tls_via(addr, HOST, &ca.roots(), NOW, WAIT).await.unwrap()
}

#[tokio::test]
async fn the_lookup_climbs_to_the_nearest_parent_with_records() {
    let (addr, asked) = dns(vec![("example.test", "issue", "letsencrypt.org")]).await;
    let r = check_caa(&[addr], HOST, Duration::from_secs(2)).await;
    assert_eq!(r.found_at.as_deref(), Some("example.test"));
    assert_eq!((r.records[0].tag.as_str(), r.records[0].value.as_str()), ("issue", "letsencrypt.org"));
    assert_eq!(*asked.lock().unwrap(), ["www.example.test", "example.test"]);
}

#[tokio::test]
async fn the_nearest_set_wins_and_the_climb_stops_below_the_root() {
    let (addr, asked) = dns(vec![("www.example.test", "issue", "digicert.com"), ("example.test", "issue", "letsencrypt.org")]).await;
    let r = check_caa(&[addr], HOST, Duration::from_secs(2)).await;
    assert_eq!(r.found_at.as_deref(), Some("www.example.test"));
    assert_eq!(asked.lock().unwrap().len(), 1);

    let (addr, asked) = dns(vec![]).await;
    let r = check_caa(&[addr], HOST, Duration::from_secs(2)).await;
    assert!(r.found_at.is_none() && r.error.is_none());
    assert_eq!(*asked.lock().unwrap(), ["www.example.test", "example.test", "test"]);
    let fs = caa_findings(&r, None);
    assert_eq!((codes(&fs), fs[0].severity), (vec!["caa_none"], Severity::Info));
}

#[tokio::test]
async fn a_failed_question_is_not_read_as_no_caa() {
    let addr = scripted::serve(|_, _| Reply::Silent).await;
    let r = check_caa(&[addr], HOST, Duration::from_millis(300)).await;
    assert!(r.error.is_some() && r.found_at.is_none());
    assert_eq!(codes(&caa_findings(&r, None)), ["caa_lookup_failed"]);
}

#[tokio::test]
async fn a_ca_the_records_forbid_is_critical() {
    let r = caa_of(vec![("www.example.test", "issue", "digicert.com")]).await;
    let tls = served_by(&Ca::root("Let's Encrypt Test CA"), &[HOST]).await;
    let fs = caa_findings(&r, Some(&tls));
    assert_eq!(codes(&fs), ["caa_forbids_issuer"]);
    assert_eq!(fs[0].severity, Severity::Critical);
    assert!(fs[0].message.contains("digicert.com"), "{}", fs[0].message);
}

#[tokio::test]
async fn an_allowed_or_unmapped_issuer_is_not_critical() {
    let r = caa_of(vec![("www.example.test", "issue", "letsencrypt.org; accounturi=https://x.test/1")]).await;
    let fs = caa_findings(&r, Some(&served_by(&Ca::root("Let's Encrypt Test CA"), &[HOST]).await));
    assert_eq!((codes(&fs), fs[0].severity), (vec!["caa_ok"], Severity::Ok));

    let fs = caa_findings(&r, Some(&served_by(&Ca::root("Homegrown Root"), &[HOST]).await));
    assert_eq!((codes(&fs), fs[0].severity), (vec!["caa_issuer_unknown"], Severity::Info));

    assert_eq!(codes(&caa_findings(&r, None)), ["caa_ok"]);
}

#[tokio::test]
async fn issuewild_is_noted_and_judges_wildcard_certificates() {
    let sets = vec![("www.example.test", "issue", "letsencrypt.org"), ("www.example.test", "issuewild", ";")];
    let r = caa_of(sets).await;
    let fs = caa_findings(&r, None);
    assert_eq!(codes(&fs), ["caa_ok", "caa_issuewild"]);
    assert!(fs[1].message.contains("forbids wildcard"), "{}", fs[1].message);

    let wild = served_by(&Ca::root("Let's Encrypt Test CA"), &["*.example.test", HOST]).await;
    let fs = caa_findings(&r, Some(&wild));
    assert!(codes(&fs).contains(&"caa_forbids_all"), "{:?}", codes(&fs));

    let r = caa_of(vec![("www.example.test", "issue", "letsencrypt.org"), ("www.example.test", "issuewild", "digicert.com")]).await;
    let fs = caa_findings(&r, Some(&wild));
    assert!(codes(&fs).contains(&"caa_forbids_issuer"), "{:?}", codes(&fs));
}

#[tokio::test]
async fn records_that_do_not_restrict_issuance_say_so() {
    let r = caa_of(vec![("www.example.test", "iodef", "mailto:security@example.test")]).await;
    assert_eq!(codes(&caa_findings(&r, None)), ["caa_no_issue"]);
    let r = caa_of(vec![("www.example.test", "issue", ";")]).await;
    let fs = caa_findings(&r, None);
    assert_eq!((codes(&fs), fs[0].severity), (vec!["caa_forbids_all"], Severity::Warning));
}

#[tokio::test]
async fn hostile_caa_values_are_cleaned_and_bounded() {
    let r = caa_of(vec![("www.example.test", "issue", "evil\x1b[2J.test"), ("www.example.test", "issue", Box::leak("x".repeat(5000).into_boxed_str()))]).await;
    assert!(r.records.iter().all(|c| !c.value.chars().any(char::is_control) && c.value.len() < 400));
}

#[tokio::test]
async fn a_server_that_staples_is_detected() {
    let ca = Ca::root("Test Root CA");
    let leaf = ca.valid_leaf(&[HOST]);
    let addr = stapling::serve_stapled(vec![leaf.der], leaf.key, Some(vec![0x30, 0x03, 0x0a, 0x01, 0x00])).await;
    let r = check_tls_via(addr, HOST, &ca.roots(), NOW, WAIT).await.unwrap();
    assert!(r.ocsp_stapled);
    let fs = ocsp_findings(HOST, 443, &r);
    assert_eq!((codes(&fs), fs[0].severity), (vec!["tls_ocsp_stapled"], Severity::Ok));
}

#[tokio::test]
async fn a_server_that_does_not_staple_gets_an_info_finding() {
    let ca = Ca::root("Test Root CA");
    let leaf = ca.valid_leaf(&[HOST]);
    let addr = stapling::serve_stapled(vec![leaf.der], leaf.key, None).await;
    let r = check_tls_via(addr, HOST, &ca.roots(), NOW, WAIT).await.unwrap();
    assert!(!r.ocsp_stapled);
    let fs = ocsp_findings(HOST, 443, &r);
    assert_eq!((codes(&fs), fs[0].severity), (vec!["tls_no_ocsp_staple"], Severity::Info));
}
