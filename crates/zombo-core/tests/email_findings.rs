#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod common;

use std::time::Duration;

use common::{FakeDns, zone};
use hickory_proto::rr::RecordType;
use zombo_core::{
    Finding, Severity,
    email_auth::{EmailAuthResult, email_auth, email_findings, spf_findings},
};

const T: Duration = Duration::from_millis(500);

async fn audit(zone_text: &str) -> EmailAuthResult {
    email_auth(FakeDns::start(zone_text).await.addr, "example.com", &[], T).await
}

async fn findings_of(zone_text: &str) -> Vec<Finding> {
    email_findings("example.com", &audit(zone_text).await)
}

fn code<'a>(fs: &'a [Finding], c: &str) -> Option<&'a Finding> {
    fs.iter().find(|f| f.code == c)
}

fn codes(fs: &[Finding]) -> Vec<&str> {
    fs.iter().map(|f| f.code).collect()
}

#[track_caller]
fn want(fs: &[Finding], expected: &[(&str, Severity)]) {
    for (c, sev) in expected {
        match code(fs, c) {
            Some(f) => assert_eq!(f.severity, *sev, "{c}: {f:?}"),
            None => panic!("no {c} Finding in {:?}", codes(fs)),
        }
    }
}

#[tokio::test]
async fn a_healthy_domain_has_only_ok_findings() {
    let fs = findings_of(&zone("email_healthy")).await;
    want(&fs, &[("spf_fail_all", Severity::Ok), ("dkim_found", Severity::Ok), ("dmarc_enforced", Severity::Ok)]);
    // The optional records (`email_*`) are not set up on this domain; they are info at most.
    for f in fs.iter().filter(|f| matches!(f.code.split('_').next(), Some("spf" | "dkim" | "dmarc"))) {
        assert_eq!(f.severity, Severity::Ok, "unexpected {f:?}");
    }
    assert_eq!(code(&fs, "dmarc_enforced").unwrap().title, "DMARC enforced (p=reject)");
}

#[tokio::test]
async fn a_domain_with_no_mail_records_is_told_so() {
    let fs = findings_of(&zone("email_missing")).await;
    want(
        &fs,
        &[
            ("spf_missing", Severity::Warning),
            ("dkim_missing", Severity::Warning),
            ("dmarc_missing", Severity::Warning),
        ],
    );
    let dkim = code(&fs, "dkim_missing").unwrap();
    assert!(dkim.recommendation.as_deref().unwrap().contains("Check more DKIM selectors"), "{dkim:?}");
    assert_eq!(
        dkim.message,
        "None of the 37 selectors checked has an active DKIM key for example.com. A provider may use a selector not on the list."
    );
}

#[tokio::test]
async fn two_spf_records_are_critical_and_nothing_else_is_said_about_spf() {
    let fs = findings_of(&zone("email_spf_multiple")).await;
    let spf: Vec<_> = fs.iter().filter(|f| f.code.starts_with("spf_")).collect();
    assert_eq!(spf.len(), 1, "{spf:?}");
    assert_eq!((spf[0].code, spf[0].severity), ("spf_multiple", Severity::Critical));
    assert_eq!(
        spf[0].message,
        "example.com publishes 2 v=spf1 records. That is a permerror: receivers treat SPF as broken."
    );
}

#[tokio::test]
async fn thirteen_lookups_are_too_many() {
    let fs = findings_of(&zone("email_spf_lookups")).await;
    want(&fs, &[("spf_too_many_lookups", Severity::Critical), ("spf_fail_all", Severity::Ok)]);
    assert!(code(&fs, "spf_permerror").is_none(), "{:?}", codes(&fs));
    assert_eq!(
        code(&fs, "spf_too_many_lookups").unwrap().message,
        "Evaluating example.com's SPF record takes 13 DNS lookups; the limit is 10, past which receivers return permerror."
    );
}

#[tokio::test]
async fn ten_lookups_are_still_fine() {
    let z = "example.com. 60 IN TXT \"v=spf1 mx mx mx mx mx mx mx mx mx mx -all\"\nexample.com. 60 IN MX 10 m.test.\n";
    let fs = findings_of(z).await;
    assert!(code(&fs, "spf_too_many_lookups").is_none(), "{:?}", codes(&fs));
    let eleven =
        "example.com. 60 IN TXT \"v=spf1 mx mx mx mx mx mx mx mx mx mx mx -all\"\nexample.com. 60 IN MX 10 m.test.\n";
    assert!(code(&findings_of(eleven).await, "spf_too_many_lookups").is_some());
}

#[tokio::test]
async fn a_truncated_walk_says_more_than_thirty() {
    let zone: String =
        (0..100).map(|i| format!("c{i}.test. 60 IN TXT \"v=spf1 include:c{}.test\"\n", i + 1)).collect::<String>()
            + "example.com. 60 IN TXT \"v=spf1 include:c0.test\"\n";
    let fs = findings_of(&zone).await;
    assert!(code(&fs, "spf_too_many_lookups").unwrap().message.contains("takes more than 30 DNS lookups"));
}

#[tokio::test]
async fn syntax_and_include_errors_are_a_permerror() {
    let fs = findings_of(&zone("email_spf_permerrors")).await;
    want(&fs, &[("spf_permerror", Severity::Critical), ("spf_softfail_all", Severity::Info)]);
    let m = &code(&fs, "spf_permerror").unwrap().message;
    assert!(m.starts_with("Receivers will return permerror for example.com: ") && m.ends_with('.'), "{m}");
    assert!(m.contains("; "));
}

#[tokio::test]
async fn three_void_lookups_are_a_permerror() {
    want(&findings_of(&zone("email_spf_voids")).await, &[("spf_permerror", Severity::Critical)]);
}

#[tokio::test]
async fn each_all_qualifier_has_its_finding() {
    let base = zone("email_spf_all_base");
    for (rec, c, sev) in [
        ("v=spf1 +all", "spf_pass_all", Severity::Critical),
        ("v=spf1 all", "spf_pass_all", Severity::Critical),
        ("v=spf1 ?all", "spf_neutral_all", Severity::Warning),
        ("v=spf1 ip4:192.0.2.1", "spf_no_all", Severity::Warning),
        ("v=spf1 ~all", "spf_softfail_all", Severity::Info),
        ("v=spf1 redirect=_spf.provider.test", "spf_softfail_all", Severity::Info),
        ("V=SPF1 ip4:192.0.2.1 -ALL", "spf_fail_all", Severity::Ok),
        ("v=spf1 -all redirect=nowhere.invalid", "spf_fail_all", Severity::Ok),
    ] {
        let fs = findings_of(&format!("example.com. 300 IN TXT \"{rec}\"\n{base}")).await;
        want(&fs, &[(c, sev)]);
        assert!(code(&fs, "spf_permerror").is_none(), "{rec}: {:?}", codes(&fs));
        assert_eq!(
            fs.iter()
                .filter(|f| matches!(
                    f.code,
                    "spf_pass_all" | "spf_neutral_all" | "spf_no_all" | "spf_softfail_all" | "spf_fail_all"
                ))
                .count(),
            1,
            "{rec}"
        );
    }
}

#[tokio::test]
async fn an_unresolved_redirect_is_not_a_missing_all() {
    let fs = findings_of(&zone("email_spf_macro_redirect")).await;
    assert!(code(&fs, "spf_no_all").is_none(), "{:?}", codes(&fs));
}

#[tokio::test]
async fn failed_lookups_inside_the_tree_are_listed() {
    let s = FakeDns::start("example.com. 60 IN TXT \"v=spf1 a:h.test -all\"\n").await.refuse(RecordType::A);
    let r = email_auth(s.addr, "example.com", &[], T).await;
    let fs = spf_findings("example.com", &r.spf);
    let f = code(&fs, "spf_lookup_failed").expect("a failed-lookups Finding");
    assert_eq!((f.severity, &*f.title), (Severity::Warning, "Some SPF lookups failed"));
    assert!(
        f.message.starts_with("These lookups got no answer, so the counts above may be low: a:h.test: "),
        "{}",
        f.message
    );
}

#[tokio::test]
async fn a_dead_resolver_gives_lookup_failed_findings_not_missing_ones() {
    let s = FakeDns::silent().await;
    let r = email_auth(s.addr, "example.com", &[], Duration::from_millis(200)).await;
    let fs = email_findings("example.com", &r);
    want(&fs, &[("spf_lookup_failed", Severity::Warning), ("dmarc_lookup_failed", Severity::Warning)]);
    assert!(code(&fs, "spf_missing").is_none() && code(&fs, "dmarc_missing").is_none());
    assert!(
        code(&fs, "dkim_missing").unwrap().message.ends_with("37 selectors could not be queried."),
        "{}",
        code(&fs, "dkim_missing").unwrap().message
    );
}

#[tokio::test]
async fn dkim_key_strength_findings_are_one_per_code() {
    let fs = findings_of(&zone("email_dkim_strength")).await;
    want(
        &fs,
        &[
            ("dkim_weak_key", Severity::Critical),
            ("dkim_short_key", Severity::Warning),
            ("dkim_revoked", Severity::Info),
            ("dkim_invalid_key", Severity::Warning),
            ("dkim_found", Severity::Ok),
        ],
    );
    let mut seen = std::collections::BTreeSet::new();
    for f in &fs {
        assert!(seen.insert(f.code), "two {} Findings", f.code);
    }
    assert_eq!(
        code(&fs, "dkim_weak_key").unwrap().message,
        "RSA keys under 1024 bits are ignored by receivers and can be factored: google (512-bit)."
    );
    assert_eq!(
        code(&fs, "dkim_short_key").unwrap().message,
        "2048 bits is the current recommendation: selector1 (1024-bit), selector2 (1024-bit), k1 (1024-bit)."
    );
    assert_eq!(
        code(&fs, "dkim_invalid_key").unwrap().message,
        "Receivers can't verify mail signed with these selectors: dkim (public key is not valid base64)."
    );
    assert_eq!(
        code(&fs, "dkim_revoked").unwrap().message,
        "An empty key (p=) means revoked; these selectors can't verify mail: s1."
    );
    // Unusable and revoked keys are not published keys.
    let found = &code(&fs, "dkim_found").unwrap().message;
    assert!(!found.contains("dkim,") && !found.contains("s1"), "{found}");
    assert_eq!(found, "example.com publishes DKIM keys for google, selector1, selector2, k1.");
}

#[tokio::test]
async fn a_revoked_key_alone_is_a_missing_key() {
    want(
        &findings_of(&zone("email_dkim_revoked")).await,
        &[("dkim_revoked", Severity::Info), ("dkim_missing", Severity::Warning)],
    );
}

#[tokio::test]
async fn custom_selectors_are_named_in_the_missing_message() {
    let z = zone("email_dkim_custom");
    let s = FakeDns::start(&z).await;
    let plain = email_auth(s.addr, "example.com", &[], T).await;
    want(&email_findings("example.com", &plain), &[("dkim_missing", Severity::Warning)]);

    let asked = email_auth(s.addr, "example.com", &["acme2024".into()], T).await;
    want(&email_findings("example.com", &asked), &[("dkim_found", Severity::Ok)]);

    let wrong = email_auth(s.addr, "example.com", &["other".into(), "more".into()], T).await;
    let fs = email_findings("example.com", &wrong);
    assert!(
        code(&fs, "dkim_missing").unwrap().message.contains("(including other, more)"),
        "{}",
        code(&fs, "dkim_missing").unwrap().message
    );
}

#[tokio::test]
async fn dmarc_monitoring_only_is_a_warning_with_two_notes() {
    let fs = findings_of(&zone("email_dmarc_monitoring")).await;
    want(
        &fs,
        &[
            ("dmarc_policy_none", Severity::Warning),
            ("dmarc_partial", Severity::Info),
            ("dmarc_no_rua", Severity::Info),
        ],
    );
    let p = code(&fs, "dmarc_partial").unwrap();
    assert!(p.message.starts_with("pct=50: "), "{}", p.message);
    assert_eq!(&*p.title, "DMARC applies to 50% of mail", "Go parity: the title carries the percentage");
}

#[tokio::test]
async fn dmarc_policies_and_their_titles() {
    for (rec, c, sev, title) in [
        (
            "v=DMARC1; p=quarantine; rua=mailto:a@x.test",
            "dmarc_enforced",
            Severity::Ok,
            "DMARC enforced (p=quarantine)",
        ),
        ("v=DMARC1; p=reject; rua=mailto:a@x.test", "dmarc_enforced", Severity::Ok, "DMARC enforced (p=reject)"),
        (
            "v=DMARC1; rua=mailto:a@x.test",
            "dmarc_invalid_policy",
            Severity::Warning,
            "DMARC record has no valid policy",
        ),
        ("v=DMARC1; p=bogus", "dmarc_invalid_policy", Severity::Warning, "DMARC record has no valid policy"),
    ] {
        let fs = findings_of(&format!("_dmarc.example.com. 60 IN TXT \"{rec}\"\n")).await;
        let f = code(&fs, c).unwrap_or_else(|| panic!("{rec}: {:?}", codes(&fs)));
        assert_eq!((f.severity, &*f.title), (sev, title), "{rec}");
    }
    let fs = findings_of("_dmarc.example.com. 60 IN TXT \"v=DMARC1; p=reject; rua=mailto:a@x.test\"\n").await;
    assert_eq!(code(&fs, "dmarc_enforced").unwrap().message, "Receivers reject failing mail for example.com.");
    assert!(code(&fs, "dmarc_no_rua").is_none() && code(&fs, "dmarc_partial").is_none());
}

#[tokio::test]
async fn two_dmarc_records_are_ignored_by_receivers() {
    let fs = findings_of(
        "_dmarc.example.com. 60 IN TXT \"v=DMARC1; p=none\"\n_dmarc.example.com. 60 IN TXT \"v=DMARC1; p=reject\"\n",
    )
    .await;
    let f = code(&fs, "dmarc_multiple").unwrap();
    assert_eq!(f.severity, Severity::Warning);
    assert_eq!(f.message, "_dmarc.example.com has 2 DMARC records, so receivers ignore DMARC for it entirely.");
    assert!(code(&fs, "dmarc_policy_none").is_none());
}

// ----- the SPF record does not name the mail provider -----

fn swap(from: &str, to: &str) -> String {
    zone("email_provider").replace(from, to)
}

#[tokio::test]
async fn spf_missing_the_mail_provider_is_flagged() {
    for (mx, include, provider) in [
        ("0 example-com.mail.protection.outlook.com.", "spf.protection.outlook.com", "Microsoft 365"),
        ("1 aspmx.l.google.com.", "_spf.google.com", "Google Workspace"),
        ("1 ALT1.ASPMX.L.GOOGLE.COM.", "_spf.google.com", "Google Workspace"),
        ("1 smtp.googlemail.com.", "_spf.google.com", "Google Workspace"),
    ] {
        let fs = findings_of(&swap("0 example-com.mail.protection.outlook.com.", mx)).await;
        let f = code(&fs, "spf_missing_provider").unwrap_or_else(|| panic!("{mx}: {:?}", codes(&fs)));
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.title.contains(provider) && f.message.contains(provider), "{f:?}");
        assert!(f.message.starts_with(&format!("Mail for example.com is handled by {provider} (MX ")), "{}", f.message);
        assert!(f.recommendation.as_deref().unwrap().contains(&format!("include:{include}")), "{f:?}");
    }
}

#[tokio::test]
async fn naming_the_provider_in_the_spf_clears_the_finding() {
    let fixed = swap(
        "\"v=spf1 include:mail.zendesk.com -all\"",
        "\"v=spf1 include:mail.zendesk.com include:spf.protection.outlook.com -all\"",
    );
    assert!(code(&findings_of(&fixed).await, "spf_missing_provider").is_none());
}

#[tokio::test]
async fn the_provider_finding_stays_silent_when_it_does_not_apply() {
    let one = "\"v=spf1 include:mail.zendesk.com -all\"";
    for (name, z) in [
        ("nested include", swap(one, "\"v=spf1 include:_spf.example.com -all\"")),
        ("redirect", swap(one, "\"v=spf1 redirect=_spf.example.com\"")),
        ("direct redirect", swap(one, "\"v=spf1 redirect=spf.protection.outlook.com\"")),
        ("no SPF record", swap(&format!("example.com. 300 IN TXT {one}"), "")),
        (
            "two SPF records",
            swap(
                &format!("example.com. 300 IN TXT {one}"),
                "example.com. 300 IN TXT \"v=spf1 -all\"\nexample.com. 300 IN TXT \"v=spf1 ~all\"",
            ),
        ),
        ("unknown provider", swap("0 example-com.mail.protection.outlook.com.", "10 mx.example.net.")),
        ("a lookalike host", swap("0 example-com.mail.protection.outlook.com.", "10 mail.notgoogle.com.")),
    ] {
        let fs = findings_of(&z).await;
        assert!(code(&fs, "spf_missing_provider").is_none(), "{name}: {:?}", code(&fs, "spf_missing_provider"));
    }
}

#[tokio::test]
async fn the_provider_finding_is_silent_when_the_spf_lookup_failed() {
    let s = FakeDns::start(&zone("email_provider")).await.refuse(RecordType::TXT);
    let r = email_auth(s.addr, "example.com", &[], T).await;
    assert!(code(&email_findings("example.com", &r), "spf_missing_provider").is_none());
}
