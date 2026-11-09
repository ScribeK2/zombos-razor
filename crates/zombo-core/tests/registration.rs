#[path = "common/registry.rs"]
mod registry;

use std::time::Duration as Wait;

use registry::{FakeHttp, Reply, fixture, rdap_domain};
use time::{Duration, OffsetDateTime};
use zombo_core::{
    Finding, Severity,
    registration::{Endpoints, RegDate, Registration, RegistrationError, Source, check_registration, registration_findings},
};

const T: Wait = Wait::from_secs(5);

fn rdap_only(tld: &str, base: &str) -> Endpoints {
    Endpoints { rdap: [(tld.into(), base.into())].into(), ..Endpoints::default() }
}

fn rfc3339(t: OffsetDateTime) -> String {
    RegDate::At(t).to_string()
}

fn code<'a>(fs: &'a [Finding], c: &str) -> Option<&'a Finding> {
    fs.iter().find(|f| f.code == c)
}
fn codes(fs: &[Finding]) -> Vec<&str> {
    fs.iter().map(|f| f.code).collect()
}

/// A registered domain expiring `days` from now, with the given EPP statuses.
fn reg(days: i64, statuses: &[&str]) -> Registration {
    let mut r = Registration::empty("example.com", Source::Rdap, "https://rdap.example/");
    r.registered = true;
    r.registrar = Some("Example Registrar".into());
    r.statuses = statuses.iter().map(|s| s.to_string()).collect();
    r.expires = Some(RegDate::At(OffsetDateTime::now_utc() + Duration::days(days) + Duration::hours(1)));
    r
}

#[test]
fn findings_by_expiry_and_status() {
    for (name, days, statuses, want, severity) in [
        ("expired", -5, &[][..], "registration_expired", Severity::Critical),
        ("expiring in 20 days", 20, &[], "registration_expiring_soon", Severity::Warning),
        ("expiring in 45 days", 45, &[], "registration_expiring", Severity::Info),
        ("client hold", 300, &["clientHold"], "registration_on_hold", Severity::Critical),
        ("server hold", 300, &["active", "serverHold"], "registration_on_hold", Severity::Critical),
        ("redemption", -40, &["redemptionPeriod"], "registration_pending_delete", Severity::Critical),
        ("pending delete", -70, &["pendingDelete"], "registration_pending_delete", Severity::Critical),
        ("pending restore", 300, &["pendingRestore"], "registration_pending_delete", Severity::Critical),
    ] {
        let fs = registration_findings("example.com", &reg(days, statuses));
        let f = code(&fs, want).unwrap_or_else(|| panic!("{name}: {:?}", codes(&fs)));
        assert_eq!(f.severity, severity, "{name}");
        if severity != Severity::Info {
            assert!(code(&fs, "registration_ok").is_none(), "{name}: a problem was also called healthy: {:?}", codes(&fs));
        }
    }
}

#[test]
fn the_finding_wording_is_the_go_wording() {
    let fs = registration_findings("example.com", &reg(20, &["clientHold", "serverHold"]));
    let soon = code(&fs, "registration_expiring_soon").unwrap();
    assert_eq!(soon.title, "Expires within 30 days");
    assert!(soon.message.starts_with("example.com expires on "), "{}", soon.message);
    assert!(soon.message.ends_with(", in 20 days."), "{}", soon.message);
    let hold = code(&fs, "registration_on_hold").unwrap();
    assert_eq!(hold.title, "Domain is on hold");
    assert!(hold.message.starts_with("example.com has status clientHold, serverHold: the registry has removed it from DNS"), "{}", hold.message);
    let one = registration_findings("example.com", &reg(0, &[]));
    assert!(code(&one, "registration_expiring_soon").unwrap().message.ends_with(", in 0 days."));
}

#[test]
fn a_healthy_domain_gets_one_ok_finding_naming_registrar_and_expiry() {
    let mut r = reg(300, &["clientTransferProhibited"]);
    r.expires = Some(RegDate::Raw("whenever".into()));
    let fs = registration_findings("example.com", &r);
    assert_eq!(codes(&fs), ["registration_ok"]);
    assert_eq!(fs[0].message, "example.com is registered with Example Registrar.");
    let fs = registration_findings("example.com", &reg(300, &[]));
    assert!(fs[0].message.starts_with("example.com is registered with Example Registrar until "), "{}", fs[0].message);
}

#[test]
fn an_ok_finding_does_not_claim_what_the_registry_never_gave() {
    let mut r = reg(0, &["connect"]);
    r.registrar = None;
    r.expires = None;
    let fs = registration_findings("example.com", &r);
    assert_eq!(fs[0].message, "example.com is registered.");
}

#[test]
fn an_info_finding_comes_with_the_ok_one() {
    let fs = registration_findings("example.com", &reg(45, &[]));
    assert_eq!(codes(&fs), ["registration_expiring", "registration_ok"]);
}

#[test]
fn not_registered_says_where_it_found_out() {
    let mut r = Registration::empty("nope.com", Source::Rdap, "https://rdap.example/");
    let fs = registration_findings("nope.com", &r);
    assert_eq!(codes(&fs), ["registration_not_registered"]);
    assert_eq!(fs[0].severity, Severity::Critical);
    assert_eq!(fs[0].message, "The registry's RDAP service has no record of nope.com.");
    r.source = Source::Whois;
    let fs = registration_findings("nope.com", &r);
    assert_eq!(fs[0].message, "The WHOIS reply for nope.com carries no registrar or dates, which means it is not registered.");
}

// RDAP

#[tokio::test]
async fn rdap_reads_the_registry() {
    let expires = OffsetDateTime::now_utc() + Duration::days(365);
    let rdap = FakeHttp::domain(200, rdap_domain(expires, &[])).await;
    let r = check_registration("example.com", &rdap_only("com", &rdap.base), T).await.unwrap();

    assert_eq!(r.source, Source::Rdap);
    assert!(r.registered);
    assert_eq!(r.registrar.as_deref(), Some("RESERVED-Internet Assigned Numbers Authority"));
    assert_eq!(r.statuses, ["clientTransferProhibited"]);
    assert_eq!(r.nameservers, ["a.iana-servers.net", "b.iana-servers.net"]);
    assert_eq!(r.created.clone().unwrap().to_string(), "1995-08-14T04:00:00Z");
    assert_eq!(r.updated.clone().unwrap().to_string(), "2024-08-14T07:01:34Z");
    assert_eq!(r.expires.clone().unwrap().to_string(), rfc3339(expires));
    assert_eq!(r.dnssec, Some(true));
    assert_eq!(r.rdap_error, None);
    assert_eq!(r.server, rdap.base);
    assert_eq!(rdap.paths(), ["/domain/example.com"]);
    let ok = registration_findings("example.com", &r);
    assert_eq!(ok.len(), 1);
    assert_eq!(ok[0].code, "registration_ok");
    assert!(ok[0].message.contains("RESERVED-Internet Assigned Numbers Authority"));
}

#[tokio::test]
async fn an_rdap_404_means_not_registered() {
    let rdap = FakeHttp::domain(404, "").await;
    let r = check_registration("example.com", &rdap_only("com", &rdap.base), T).await.unwrap();
    assert!(!r.registered);
    assert_eq!(r.source, Source::Rdap);
    let fs = registration_findings("example.com", &r);
    assert_eq!(codes(&fs), ["registration_not_registered"]);
}

#[tokio::test]
async fn a_sparse_rdap_record_is_still_registered() {
    // The empty-looking heuristic is for WHOIS only: thin RDAP data is a real registration.
    let rdap = FakeHttp::domain(200, fixture("rdap_sparse.json")).await;
    let r = check_registration("example.com", &rdap_only("com", &rdap.base), T).await.unwrap();
    assert!(r.registered);
    assert!(r.registrar.is_none() && r.statuses.is_empty() && r.nameservers.is_empty());
}

#[tokio::test]
async fn odd_but_valid_rdap_shapes_do_not_panic() {
    let rdap = FakeHttp::domain(200, fixture("rdap_odd_shapes.json")).await;
    let r = check_registration("example.com", &rdap_only("com", &rdap.base), T).await.unwrap();
    assert!(r.registered);
    assert_eq!(r.registrar, None);
}

#[tokio::test]
async fn the_registered_name_of_a_private_suffix_site_is_what_is_asked() {
    // foo.github.io is a site of its own, but it is registered as github.io.
    let rdap = FakeHttp::domain(200, rdap_domain(OffsetDateTime::now_utc() + Duration::days(365), &[])).await;
    let r = check_registration("foo.github.io", &rdap_only("io", &rdap.base), T).await.unwrap();
    assert_eq!(r.domain, "github.io");
    assert_eq!(rdap.paths(), ["/domain/github.io"]);
}

#[tokio::test]
async fn rdap_follows_a_few_redirects_and_no_more() {
    let body = rdap_domain(OffsetDateTime::now_utc() + Duration::days(365), &[]);
    let hop = FakeHttp::start(move |path| match path {
        "/domain/example.com" => Reply::redirect("/moved/1"),
        "/moved/1" => Reply::redirect("/moved/2"),
        "/moved/2" => Reply::new(200, body.clone()),
        _ => Reply::new(404, ""),
    })
    .await;
    let r = check_registration("example.com", &rdap_only("com", &hop.base), T).await.unwrap();
    assert!(r.registered);

    let endless = FakeHttp::start(|_| Reply::redirect("/again")).await;
    let err = check_registration("example.com", &rdap_only("com", &endless.base), T).await.unwrap_err();
    assert!(matches!(err, RegistrationError::Rdap(_)), "{err}");
    assert!(endless.hits() <= 6, "followed {} redirects", endless.hits());
}

#[tokio::test]
async fn an_rdap_server_error_or_garbage_is_an_error_not_a_panic() {
    let big = vec![b' '; 2 << 20];
    let nested = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    for (name, status, body) in [
        ("500", 500, b"".to_vec()),
        ("not json", 200, b"<html>maintenance</html>".to_vec()),
        ("wrong types", 200, br#"{"status": "active", "events": 7}"#.to_vec()),
        ("truncated", 200, br#"{"status": ["active"#.to_vec()),
        ("deeply nested", 200, nested.into_bytes()),
        ("over the size cap", 200, big),
        ("empty", 200, vec![]),
    ] {
        let rdap = FakeHttp::domain(status, body).await;
        let err = check_registration("example.com", &rdap_only("com", &rdap.base), T).await.unwrap_err();
        assert!(matches!(err, RegistrationError::Rdap(_)), "{name}: {err}");
    }
}

#[tokio::test]
async fn a_tld_without_rdap_is_an_error_when_there_is_no_whois() {
    let err = check_registration("nope.test", &Endpoints::default(), T).await.unwrap_err();
    assert!(err.to_string().contains("no RDAP service for .test"), "{err}");
}

#[tokio::test]
async fn names_that_could_smuggle_a_query_are_refused() {
    for bad in ["", "example", "exa mple.com", "example.com\r\nevil", "a/b.com", "-T dn example.de"] {
        let err = check_registration(bad, &Endpoints::default(), T).await.unwrap_err();
        assert!(matches!(err, RegistrationError::BadName(_)), "{bad:?}: {err}");
    }
}
