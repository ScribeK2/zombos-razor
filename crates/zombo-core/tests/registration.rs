use time::{Duration, OffsetDateTime};
use zombo_core::{
    Finding, Severity,
    registration::{RegDate, Registration, Source, registration_findings},
};

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
