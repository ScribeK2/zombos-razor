#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#[path = "common/registry.rs"]
mod registry;

use std::time::Duration as Wait;

use registry::{FakeHttp, FakeWhois, Reply, closed_port, fixture, rdap_domain, silent, whois_verisign};
use time::{Duration, OffsetDateTime};
use zombo_core::{
    Finding, Severity,
    registration::{
        Endpoints, RegDate, Registration, RegistrationError, Source, check_registration, registration_findings,
    },
};

const T: Wait = Wait::from_secs(5);

/// The real endpoints with every WHOIS server pointed at a closed port, so no test reaches the network.
const CLOSED: &str = "127.0.0.1:1";

fn offline() -> Endpoints {
    Endpoints { whois_iana: CLOSED.into(), ..Endpoints::default() }
}

fn rdap_only(tld: &str, base: &str) -> Endpoints {
    Endpoints { rdap: [(tld.into(), base.into())].into(), whois: [(tld.into(), CLOSED.into())].into(), ..offline() }
}

fn rdap_whois(tld: &str, base: &str, whois: &str) -> Endpoints {
    Endpoints { rdap: [(tld.into(), base.into())].into(), whois: [(tld.into(), whois.into())].into(), ..offline() }
}

fn whois_only(tld: &str, whois: &str) -> Endpoints {
    Endpoints { whois: [(tld.into(), whois.into())].into(), ..offline() }
}

fn expires_in(days: i64) -> OffsetDateTime {
    OffsetDateTime::now_utc() + Duration::days(days)
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
            assert!(
                code(&fs, "registration_ok").is_none(),
                "{name}: a problem was also called healthy: {:?}",
                codes(&fs)
            );
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
    assert!(
        hold.message.starts_with("example.com has status clientHold, serverHold: the registry has removed it from DNS"),
        "{}",
        hold.message
    );
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
    assert_eq!(
        fs[0].message,
        "The WHOIS reply for nope.com carries no registrar or dates, which means it is not registered."
    );
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
    assert!(matches!(err, RegistrationError::Unavailable { .. }), "{err}");
    assert!(endless.hits() <= 6, "followed {} redirects", endless.hits());
}

#[tokio::test]
async fn an_rdap_server_error_or_garbage_is_an_error_not_a_panic() {
    // Valid JSON, so only the size cap can reject it.
    let big = format!(r#"{{"status": ["active"], "notes": "{}"}}"#, "x".repeat(2 << 20)).into_bytes();
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
        assert!(matches!(err, RegistrationError::Unavailable { .. }), "{name}: {err}");
    }
}

#[tokio::test]
async fn a_tld_without_rdap_is_an_error_when_there_is_no_whois() {
    let err = check_registration("nope.test", &offline(), T).await.unwrap_err();
    assert!(err.to_string().contains("no RDAP service for .test"), "{err}");
}

#[tokio::test]
async fn names_that_could_smuggle_a_query_are_refused() {
    for bad in ["", "example", "exa mple.com", "example.com\r\nevil", "a/b.com", "-T dn example.de"] {
        let err = check_registration(bad, &offline(), T).await.unwrap_err();
        assert!(matches!(err, RegistrationError::BadName(_)), "{bad:?}: {err}");
    }
}

// WHOIS and the fallback

const IANA_NAME: &str = "RESERVED-Internet Assigned Numbers Authority";

#[tokio::test]
async fn rdap_that_answers_is_not_second_guessed_by_whois() {
    let rdap = FakeHttp::domain(200, rdap_domain(expires_in(365), &[])).await;
    let whois = FakeWhois::reply("should not be asked").await;
    let r = check_registration("example.com", &rdap_whois("com", &rdap.base, &whois.addr), T).await.unwrap();
    assert_eq!(r.source, Source::Rdap);
    assert!(whois.queries().is_empty());
}

#[tokio::test]
async fn an_authoritative_rdap_404_does_not_ask_whois() {
    let rdap = FakeHttp::domain(404, "").await;
    let whois = FakeWhois::reply("should not be asked").await;
    let r = check_registration("example.com", &rdap_whois("com", &rdap.base, &whois.addr), T).await.unwrap();
    assert!(!r.registered);
    assert!(whois.queries().is_empty());
}

#[tokio::test]
async fn whois_answers_when_rdap_fails() {
    let expires = expires_in(20).replace_nanosecond(0).unwrap();
    let rdap = FakeHttp::domain(500, "").await;
    let whois = FakeWhois::reply(whois_verisign(&rfc3339(expires))).await;
    let r = check_registration("example.com", &rdap_whois("com", &rdap.base, &whois.addr), T).await.unwrap();

    assert!(rdap.hits() > 0, "RDAP was not tried first");
    assert!(r.rdap_error.as_deref().is_some_and(|e| e.contains("500")), "{:?}", r.rdap_error);
    assert_eq!(r.source, Source::Whois);
    assert_eq!(r.server, whois.addr);
    assert!(r.registered);
    assert_eq!(r.registrar.as_deref(), Some(IANA_NAME));
    assert_eq!(r.expires.clone().unwrap().to_string(), rfc3339(expires));
    assert_eq!(r.created.clone().unwrap().to_string(), "1995-08-14T04:00:00Z");
    assert_eq!(r.updated.clone().unwrap().to_string(), "2024-08-14T07:01:34Z");
    assert_eq!(r.statuses, ["clientDeleteProhibited", "clientHold"]);
    assert_eq!(r.nameservers, ["a.iana-servers.net", "b.iana-servers.net"]);
    assert_eq!(r.dnssec, Some(true));
    assert_eq!(whois.queries(), ["example.com"]);
    // Findings apply to a WHOIS result just the same.
    let fs = registration_findings("example.com", &r);
    assert_eq!(code(&fs, "registration_on_hold").unwrap().severity, Severity::Critical);
    assert_eq!(code(&fs, "registration_expiring_soon").unwrap().severity, Severity::Warning);
}

#[tokio::test]
async fn whois_serves_a_tld_without_rdap() {
    // .test is in no RDAP bootstrap.
    let whois = FakeWhois::reply(whois_verisign(&rfc3339(expires_in(700)))).await;
    let r = check_registration("nope.test", &whois_only("test", &whois.addr), T).await.unwrap();
    assert_eq!((r.source, r.registered, r.domain.as_str()), (Source::Whois, true, "nope.test"));
    assert!(r.rdap_error.unwrap().contains("no RDAP service for .test"));
}

#[tokio::test]
async fn an_iana_referral_is_followed_once() {
    let registry = FakeWhois::reply(whois_verisign(&rfc3339(expires_in(700)))).await;
    let iana = FakeWhois::reply(fixture("whois_iana_refer.txt").replace("__SERVER__", "127.0.0.1")).await;
    let port: u16 = registry.addr.rsplit(':').next().unwrap().parse().unwrap();
    let ep = Endpoints { whois_iana: iana.addr.clone(), whois_referral_port: port, ..Endpoints::default() };
    let r = check_registration("nope.test", &ep, T).await.unwrap();
    assert_eq!(r.registrar.as_deref(), Some(IANA_NAME));
    assert_eq!(r.server, registry.addr);
    assert_eq!(iana.queries(), ["nope.test"]);
    assert_eq!(registry.queries(), ["nope.test"]);
}

#[tokio::test]
async fn an_unusable_iana_referral_is_an_error() {
    for (name, reply) in [
        ("none", "domain: TEST\n".to_string()),
        ("junk after the host", fixture("whois_iana_refer.txt").replace("__SERVER__", "host.example:1 ; junk")),
        ("a port", fixture("whois_iana_refer.txt").replace("__SERVER__", "host.example:25")),
    ] {
        let iana = FakeWhois::reply(reply).await;
        let ep = Endpoints { whois_iana: iana.addr.clone(), ..Endpoints::default() };
        let err = check_registration("nope.test", &ep, T).await.unwrap_err();
        assert!(matches!(err, RegistrationError::Unavailable { .. }), "{name}: {err}");
    }
}

#[tokio::test]
async fn an_empty_looking_whois_reply_means_not_registered() {
    let whois = FakeWhois::reply(fixture("whois_no_match.txt")).await;
    let r = check_registration("nope.test", &whois_only("test", &whois.addr), T).await.unwrap();
    assert_eq!(r.source, Source::Whois);
    assert!(!r.registered);
    assert_eq!(
        code(&registration_findings("nope.test", &r), "registration_not_registered").unwrap().severity,
        Severity::Critical
    );
}

#[tokio::test]
async fn registry_formats_without_a_registrar_or_dates() {
    for (name, file, registrar, registered) in [
        // DENIC gives no registrar or dates for a registered .de name.
        ("denic connect", "whois_denic_connect.txt", None, true),
        ("denic free", "denic_free.txt", None, false),
        // EURid puts the registrar on the next line.
        ("eurid block", "whois_eurid_block.txt", Some("Example Registrar SA"), true),
    ] {
        let whois = FakeWhois::reply(fixture(file)).await;
        let r = check_registration("nope.test", &whois_only("test", &whois.addr), T).await.unwrap();
        assert_eq!((r.registered, r.registrar.as_deref()), (registered, registrar), "{name}");
        let fs = registration_findings("nope.test", &r);
        assert_eq!(code(&fs, "registration_not_registered").is_some(), !registered, "{name}: {:?}", codes(&fs));
    }
}

#[tokio::test]
async fn whois_dates_in_other_formats_are_normalised() {
    let whois =
        FakeWhois::reply("Registrar: X\nCreated On: 14-Aug-1995\nExpires: 2030.01.02\nLast Updated: whenever\n").await;
    let r = check_registration("nope.test", &whois_only("test", &whois.addr), T).await.unwrap();
    assert_eq!(r.created.unwrap().to_string(), "1995-08-14T00:00:00Z");
    assert_eq!(r.expires.unwrap().to_string(), "2030-01-02T00:00:00Z");
    assert_eq!(r.updated, Some(RegDate::Raw("whenever".into())));
}

#[tokio::test]
async fn it_fails_when_neither_rdap_nor_whois_answers() {
    let rdap = FakeHttp::domain(502, "").await;
    let closed = closed_port().await;
    let err = check_registration("example.com", &rdap_whois("com", &rdap.base, &closed), T).await.unwrap_err();
    assert!(matches!(err, RegistrationError::Unavailable { .. }), "{err}");
    assert!(err.to_string().starts_with("RDAP: RDAP server answered 502 Bad Gateway; WHOIS: "), "{err}");
}

#[tokio::test]
async fn a_silent_server_ends_at_the_deadline() {
    let rdap = silent().await;
    let started = std::time::Instant::now();
    let err = check_registration("example.com", &rdap_only("com", &format!("http://{rdap}/")), Wait::from_millis(400))
        .await
        .unwrap_err();
    assert!(matches!(err, RegistrationError::TimedOut), "{err}");
    assert!(started.elapsed() < Wait::from_secs(3), "took {:?}", started.elapsed());

    let whois = silent().await;
    let err = check_registration("nope.test", &whois_only("test", &whois), Wait::from_millis(400)).await.unwrap_err();
    assert!(matches!(err, RegistrationError::TimedOut), "{err}");
}

#[tokio::test]
async fn an_oversized_or_binary_whois_reply_is_capped_not_fatal() {
    let mut huge = b"Registrar: Early Registrar\n".to_vec();
    huge.extend(std::iter::repeat_n(b'x', 2 << 20));
    huge.extend(b"\nExpires: 2030-01-02\n");
    let whois = FakeWhois::reply(huge).await;
    let r = check_registration("nope.test", &whois_only("test", &whois.addr), T).await.unwrap();
    assert_eq!(r.registrar.as_deref(), Some("Early Registrar"));
    assert_eq!(r.expires, None, "read past the 1 MiB cap");

    let whois = FakeWhois::reply(vec![
        0xff, 0xfe, b'\n', 0x00, b':', b'\n', b'S', b't', b'a', b't', b'u', b's', b':', b' ', 0xc3, 0x28, b'\n',
    ])
    .await;
    let r = check_registration("nope.test", &whois_only("test", &whois.addr), T).await.unwrap();
    assert_eq!(r.source, Source::Whois);
}

#[tokio::test]
async fn an_empty_whois_reply_is_an_error() {
    let whois = FakeWhois::reply("  \r\n").await;
    let err = check_registration("nope.test", &whois_only("test", &whois.addr), T).await.unwrap_err();
    assert!(err.to_string().contains("empty reply from WHOIS server"), "{err}");
}

// DENIC (.de) answers a bare name with too little, so it is asked in its own form.

/// Like whois.denic.de: the detailed reply for "-T dn,ace <name>", the plain one otherwise.
async fn fake_denic(detailed: &str, plain: &str) -> FakeWhois {
    let (detailed, plain) = (detailed.to_string(), plain.to_string());
    FakeWhois::start(move |q| if q.starts_with("-T dn,ace ") { detailed.clone().into() } else { plain.clone().into() })
        .await
}

#[tokio::test]
async fn a_registered_de_domain_is_registered() {
    let denic = fake_denic(&fixture("denic_detailed.txt"), &fixture("denic_plain.txt")).await;
    let r = check_registration("example.de", &whois_only("de", &denic.addr), T).await.unwrap();
    assert_eq!(denic.queries(), ["-T dn,ace example.de"]);
    assert!(r.registered);
    assert_eq!(r.nameservers.len(), 4);
    assert_eq!(r.nameservers[0], "ns1.denic.de");
    let fs = registration_findings("example.de", &r);
    assert_eq!(codes(&fs), ["registration_ok"]);
    assert!(!fs[0].message.contains(" with ") && !fs[0].message.contains(" until "), "{}", fs[0].message);
}

#[tokio::test]
async fn status_connect_alone_means_registered() {
    let denic = fake_denic(&fixture("denic_plain.txt"), &fixture("denic_plain.txt")).await;
    let r = check_registration("example.de", &whois_only("de", &denic.addr), T).await.unwrap();
    assert!(r.registered);
}

#[tokio::test]
async fn a_free_de_domain_is_not_registered() {
    let denic = fake_denic(&fixture("denic_free.txt"), &fixture("denic_free.txt")).await;
    let r = check_registration("example.de", &whois_only("de", &denic.addr), T).await.unwrap();
    assert!(!r.registered);
    assert!(code(&registration_findings("example.de", &r), "registration_not_registered").is_some());
}

#[tokio::test]
async fn an_internationalised_de_domain_is_queried_in_ace_form() {
    // DENIC answers "Status: invalid" to a bare xn-- name; "-T dn,ace" is the form that works.
    let denic = fake_denic(&fixture("denic_idn_detailed.txt"), &fixture("denic_idn_plain.txt")).await;
    let r = check_registration("xn--bcher-kva.de", &whois_only("de", &denic.addr), T).await.unwrap();
    assert_eq!(denic.queries(), ["-T dn,ace xn--bcher-kva.de"]);
    assert!(r.registered);
}

#[tokio::test]
async fn an_invalid_answer_fails_rather_than_saying_not_registered() {
    let denic = fake_denic(&fixture("denic_invalid.txt"), &fixture("denic_invalid.txt")).await;
    let err = check_registration("example.de", &whois_only("de", &denic.addr), T).await.unwrap_err();
    assert!(err.to_string().contains("is invalid"), "{err}");
}

#[test]
fn the_registrar_is_named_inside_the_recommendation_that_needs_one() {
    for (days, statuses, want, text) in [
        (
            -5,
            &[][..],
            "registration_expired",
            "Renew it at the registrar (Example Registrar) now, before it enters redemption",
        ),
        (300, &["clientHold"], "registration_on_hold", "Contact the registrar (Example Registrar) to find out why"),
        (
            -40,
            &["redemptionPeriod"],
            "registration_pending_delete",
            "Ask the registrar (Example Registrar) to restore it immediately",
        ),
    ] {
        let fs = registration_findings("example.com", &reg(days, statuses));
        let f = code(&fs, want).unwrap_or_else(|| panic!("{want}: {:?}", codes(&fs)));
        let rec = f.recommendation.as_deref().unwrap_or_default();
        assert!(rec.contains(text), "{want}: {rec}");
    }
}

#[test]
fn without_a_registrar_name_the_recommendation_has_no_empty_parentheses() {
    let mut r = reg(-5, &[]);
    r.registrar = None;
    let fs = registration_findings("example.com", &r);
    let rec = code(&fs, "registration_expired").unwrap().recommendation.as_deref().unwrap_or_default().to_string();
    assert!(rec.starts_with("Renew it at the registrar now,"), "{rec}");
}
