//! TLS-RPT, BIMI and the MTA-STS TXT record: DNS only, no Go oracle.

mod common;

use std::time::Duration;

use common::{FakeDns, zone};
use hickory_proto::rr::RecordType;
use zombo_core::{
    Finding, Severity,
    email_auth::{email_auth, email_findings},
};

const T: Duration = Duration::from_millis(500);

async fn findings_of(zone_text: &str) -> Vec<Finding> {
    let r = email_auth(FakeDns::start(zone_text).await.addr, "example.com", &[], T).await;
    email_findings("example.com", &r)
}

fn only<'a>(fs: &'a [Finding], prefix: &str) -> &'a Finding {
    let hits: Vec<_> = fs.iter().filter(|f| f.code.starts_with(prefix)).collect();
    assert_eq!(hits.len(), 1, "{prefix}: {:?}", fs.iter().map(|f| f.code).collect::<Vec<_>>());
    hits[0]
}

#[tokio::test]
async fn published_records_are_ok_and_say_where_reports_go() {
    let fs = findings_of(&zone("email_optional")).await;
    let (t, b, m) = (only(&fs, "email_tlsrpt_"), only(&fs, "email_bimi_"), only(&fs, "email_mtasts_"));
    assert_eq!((t.code, t.severity), ("email_tlsrpt_ok", Severity::Ok));
    assert_eq!((b.code, b.severity), ("email_bimi_ok", Severity::Ok));
    assert_eq!((m.code, m.severity), ("email_mtasts_ok", Severity::Ok));
    assert!(t.message.contains("mailto:tls@example.com"), "{}", t.message);
    assert!(b.message.contains("https://example.com/logo.svg") && b.message.contains("evidence document"), "{}", b.message);
    // The record is all that was checked, and the finding says so.
    assert!(m.message.contains("20240101T000000") && m.message.contains("not fetched"), "{}", m.message);
}

#[tokio::test]
async fn absent_records_are_info_not_a_problem() {
    let fs = findings_of("example.com. 60 IN A 192.0.2.1\n").await;
    for (prefix, code) in [("email_tlsrpt_", "email_tlsrpt_missing"), ("email_bimi_", "email_bimi_missing"), ("email_mtasts_", "email_mtasts_missing")] {
        let f = only(&fs, prefix);
        assert_eq!((f.code, f.severity), (code, Severity::Info));
        assert!(f.recommendation.is_some_and(|r| r.starts_with("Optional.")), "{f:?}");
    }
}

#[tokio::test]
async fn a_tls_rpt_record_must_have_a_mailto_or_https_address() {
    for rua in ["rua=http://x.test/r", "rua=ftp://x.test/r", "rua=", "rua=mailto:a@x.test,gopher://y", ""] {
        let fs = findings_of(&format!("_smtp._tls.example.com. 60 IN TXT \"v=TLSRPTv1; {rua}\"\n")).await;
        let f = only(&fs, "email_tlsrpt_");
        assert_eq!((f.code, f.severity), ("email_tlsrpt_invalid", Severity::Warning), "{rua:?}");
    }
    for rua in ["rua=mailto:a@x.test", "rua=https://x.test/r", "rua=mailto:a@x.test,https://x.test/r"] {
        let fs = findings_of(&format!("_smtp._tls.example.com. 60 IN TXT \"v=TLSRPTv1; {rua}\"\n")).await;
        assert_eq!(only(&fs, "email_tlsrpt_").code, "email_tlsrpt_ok", "{rua}");
    }
}

#[tokio::test]
async fn bimi_needs_an_https_logo() {
    for rec in ["v=BIMI1; a=https://x.test/vmc.pem", "v=BIMI1; l=http://x.test/l.svg", "v=BIMI1; l=https://x.test/l.svg; a=http://x.test/v.pem", "v=BIMI1; l=data:image/svg+xml;base64,AAAA"] {
        let fs = findings_of(&format!("default._bimi.example.com. 60 IN TXT \"{rec}\"\n")).await;
        let f = only(&fs, "email_bimi_");
        assert_eq!((f.code, f.severity), ("email_bimi_invalid", Severity::Warning), "{rec}");
    }
}

#[tokio::test]
async fn bimi_with_an_empty_logo_is_a_deliberate_opt_out() {
    let fs = findings_of("default._bimi.example.com. 60 IN TXT \"v=BIMI1; l=;\"\n").await;
    let f = only(&fs, "email_bimi_");
    assert_eq!(f.code, "email_bimi_ok");
    assert!(f.message.contains("declines"), "{}", f.message);
}

#[tokio::test]
async fn bimi_without_an_evidence_document_is_still_ok() {
    let fs = findings_of("default._bimi.example.com. 60 IN TXT \"v=BIMI1; l=https://x.test/l.svg\"\n").await;
    let f = only(&fs, "email_bimi_");
    assert_eq!(f.code, "email_bimi_ok");
    assert!(f.message.contains("no a= evidence document"), "{}", f.message);
}

#[tokio::test]
async fn an_mta_sts_id_is_one_to_thirty_two_letters_and_digits() {
    for id in ["", "id=", "id=a-b", &format!("id={}", "a".repeat(33)), "id=é"] {
        let fs = findings_of(&format!("_mta-sts.example.com. 60 IN TXT \"v=STSv1; {id}\"\n")).await;
        let f = only(&fs, "email_mtasts_");
        assert_eq!((f.code, f.severity), ("email_mtasts_invalid", Severity::Warning), "{id:?}");
    }
    let fs = findings_of(&format!("_mta-sts.example.com. 60 IN TXT \"v=STSv1; id={}\"\n", "a1".repeat(16))).await;
    assert_eq!(only(&fs, "email_mtasts_").code, "email_mtasts_ok");
}

#[tokio::test]
async fn two_records_are_a_warning_for_each_kind() {
    let z = "_smtp._tls.example.com. 60 IN TXT \"v=TLSRPTv1; rua=mailto:a@x.test\"\n_smtp._tls.example.com. 60 IN TXT \"v=TLSRPTv1; rua=mailto:b@x.test\"\n\
             default._bimi.example.com. 60 IN TXT \"v=BIMI1; l=https://x.test/a.svg\"\ndefault._bimi.example.com. 60 IN TXT \"v=BIMI1; l=https://x.test/b.svg\"\n\
             _mta-sts.example.com. 60 IN TXT \"v=STSv1; id=1\"\n_mta-sts.example.com. 60 IN TXT \"v=STSv1; id=2\"\n";
    let fs = findings_of(z).await;
    for (prefix, code) in [("email_tlsrpt_", "email_tlsrpt_multiple"), ("email_bimi_", "email_bimi_multiple"), ("email_mtasts_", "email_mtasts_multiple")] {
        let f = only(&fs, prefix);
        assert_eq!((f.code, f.severity), (code, Severity::Warning));
        assert!(f.message.contains("2 "), "{}", f.message);
    }
}

#[tokio::test]
async fn a_record_with_another_version_or_a_stray_txt_is_not_one_of_them() {
    let z = "_smtp._tls.example.com. 60 IN TXT \"hello\"\ndefault._bimi.example.com. 60 IN TXT \"v=BIMI2; l=https://x.test/a.svg\"\n_mta-sts.example.com. 60 IN TXT \"id=1; v=STSv1\"\n";
    let fs = findings_of(z).await;
    assert_eq!(only(&fs, "email_tlsrpt_").code, "email_tlsrpt_missing");
    assert_eq!(only(&fs, "email_bimi_").code, "email_bimi_missing");
    assert_eq!(only(&fs, "email_mtasts_").code, "email_mtasts_missing");
}

#[tokio::test]
async fn a_failed_lookup_is_a_warning_not_a_missing_record() {
    let s = FakeDns::start(&zone("email_optional")).await.refuse(RecordType::TXT);
    let r = email_auth(s.addr, "example.com", &[], T).await;
    let fs = email_findings("example.com", &r);
    for (prefix, code) in [("email_tlsrpt_", "email_tlsrpt_lookup_failed"), ("email_bimi_", "email_bimi_lookup_failed"), ("email_mtasts_", "email_mtasts_lookup_failed")] {
        let f = only(&fs, prefix);
        assert_eq!((f.code, f.severity), (code, Severity::Warning));
    }
}

#[tokio::test]
async fn these_findings_are_never_critical() {
    for z in [zone("email_optional"), "example.com. 60 IN A 192.0.2.1\n".into(), "_smtp._tls.example.com. 60 IN TXT \"v=TLSRPTv1; rua=bad\"\n".into()] {
        for f in findings_of(&z).await.iter().filter(|f| f.code.starts_with("email_")) {
            assert!(f.severity != Severity::Critical, "{f:?}");
        }
    }
}
