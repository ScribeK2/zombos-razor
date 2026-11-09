//! The DNS-only mail records with no Go oracle: TLS-RPT (RFC 8460), BIMI and
//! the MTA-STS TXT record (RFC 8461). The MTA-STS policy file is not fetched.

use serde::Serialize;

use super::{has_version, tags};

/// `_smtp._tls.<domain>`: where senders send reports of failed TLS delivery.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TlsRpt {
    /// Every TXT record that starts `v=TLSRPTv1`.
    pub records: Vec<String>,
    /// The `rua=` URIs of the record, when there is exactly one.
    pub rua: Vec<String>,
    /// The TXT lookup got no answer.
    pub lookup_error: Option<String>,
}

/// `default._bimi.<domain>`: the logo a mail client may show beside the domain's mail.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Bimi {
    pub records: Vec<String>,
    /// `l=`: the logo URL. `Some("")` is a deliberate opt-out.
    pub logo: Option<String>,
    /// `a=`: the evidence document (VMC) URL.
    pub authority: Option<String>,
    pub lookup_error: Option<String>,
}

/// `_mta-sts.<domain>`: says a policy file exists, and its version.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MtaSts {
    pub records: Vec<String>,
    /// `id=`: changes whenever the policy file changes.
    pub id: Option<String>,
    pub lookup_error: Option<String>,
}

fn matching(txts: &[String], version: &str) -> Vec<String> {
    txts.iter().filter(|t| has_version(t, version)).cloned().collect()
}

/// The value of a tag, only when exactly one record is published: with two,
/// receivers discard both.
fn single(records: &[String]) -> Option<std::collections::BTreeMap<String, String>> {
    (records.len() == 1).then(|| tags(&records[0]))
}

pub fn parse_tls_rpt(txts: &[String]) -> TlsRpt {
    let records = matching(txts, "TLSRPTv1");
    let rua = single(&records).map(|t| t.get("rua").map_or_else(Vec::new, |r| r.split(',').filter(|u| !u.is_empty()).map(String::from).collect()));
    TlsRpt { rua: rua.unwrap_or_default(), records, lookup_error: None }
}

pub fn parse_bimi(txts: &[String]) -> Bimi {
    let records = matching(txts, "BIMI1");
    let t = single(&records).unwrap_or_default();
    Bimi { logo: t.get("l").cloned(), authority: t.get("a").cloned(), records, lookup_error: None }
}

pub fn parse_mta_sts(txts: &[String]) -> MtaSts {
    let records = matching(txts, "STSv1");
    let id = single(&records).and_then(|t| t.get("id").cloned());
    MtaSts { id, records, lookup_error: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(rs: &[&str]) -> Vec<String> {
        rs.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn tls_rpt_reads_its_report_addresses() {
        let r = parse_tls_rpt(&v(&["google-site-verification=x", "v=TLSRPTv1; rua=mailto:a@x.test, https://r.x.test/tls"]));
        assert_eq!(r.records.len(), 1);
        assert_eq!(r.rua, ["mailto:a@x.test", "https://r.x.test/tls"]);
    }

    #[test]
    fn two_records_are_kept_but_not_read() {
        let r = parse_tls_rpt(&v(&["v=TLSRPTv1; rua=mailto:a@x.test", "v=TLSRPTv1; rua=mailto:b@x.test"]));
        assert_eq!(r.records.len(), 2);
        assert!(r.rua.is_empty());
    }

    #[test]
    fn a_record_with_another_version_is_not_a_tls_rpt_record() {
        assert!(parse_tls_rpt(&v(&["v=TLSRPTv2; rua=mailto:a@x.test", "rua=mailto:a@x.test; v=TLSRPTv1"])).records.is_empty());
    }

    #[test]
    fn bimi_reads_logo_and_evidence() {
        let b = parse_bimi(&v(&["v=BIMI1; l=https://x.test/logo.svg; a=https://x.test/vmc.pem"]));
        assert_eq!((b.logo.as_deref(), b.authority.as_deref()), (Some("https://x.test/logo.svg"), Some("https://x.test/vmc.pem")));
        let opt_out = parse_bimi(&v(&["v=BIMI1; l=;"]));
        assert_eq!((opt_out.logo.as_deref(), opt_out.authority), (Some(""), None));
        assert_eq!(parse_bimi(&v(&["v=BIMI1; a=https://x.test/vmc.pem"])).logo, None);
    }

    #[test]
    fn mta_sts_reads_its_id() {
        let m = parse_mta_sts(&v(&["v=STSv1; id=20240101T000000"]));
        assert_eq!((m.records.len(), m.id.as_deref()), (1, Some("20240101T000000")));
        assert_eq!(parse_mta_sts(&v(&["v=STSv1"])).id, None);
        assert_eq!(parse_mta_sts(&v(&["v=STSv1; id=a", "v=STSv1; id=b"])).id, None);
    }

    #[test]
    fn hostile_records_do_not_panic() {
        let big = format!("v=TLSRPTv1; rua={}", "mailto:a@x.test,".repeat(4_000));
        for junk in ["", ";", "v=TLSRPTv1;;;rua", "v=BIMI1; l", "v=STSv1; id=\u{1b}[2J", big.as_str()] {
            let t = v(&[junk]);
            let _ = (parse_tls_rpt(&t), parse_bimi(&t), parse_mta_sts(&t));
        }
    }
}
