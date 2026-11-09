//! DMARC: the policy record at `_dmarc.<domain>`.

use serde::Serialize;

use super::{has_version, query::Dns, tags};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    None,
    Quarantine,
    Reject,
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Policy::None => "none",
            Policy::Quarantine => "quarantine",
            Policy::Reject => "reject",
        })
    }
}

impl Policy {
    fn parse(s: &str) -> Option<Policy> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Some(Policy::None),
            "quarantine" => Some(Policy::Quarantine),
            "reject" => Some(Policy::Reject),
            _ => None,
        }
    }
}

/// `adkim` and `aspf`: whether a subdomain of the From domain also aligns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Alignment {
    Relaxed,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DmarcRecord {
    /// `None` when `p=` is missing or not none, quarantine or reject.
    pub policy: Option<Policy>,
    pub subdomain_policy: Option<Policy>,
    /// Percent of failing mail the policy applies to; 100 when absent or out of range.
    pub pct: u8,
    pub rua: Vec<String>,
    pub ruf: Vec<String>,
    pub adkim: Alignment,
    pub aspf: Alignment,
}

/// What an audit of one domain's DMARC found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DmarcAudit {
    /// Every `v=DMARC1` record at `_dmarc.<domain>`.
    pub records: Vec<String>,
    /// The single record; with two, receivers ignore DMARC.
    pub parsed: Option<DmarcRecord>,
    /// The TXT lookup got no answer.
    pub lookup_error: Option<String>,
}

pub(crate) async fn dmarc_audit(dns: Dns, domain: &str) -> DmarcAudit {
    let mut audit = DmarcAudit::default();
    match dns.txt(&format!("_dmarc.{domain}")).await {
        Ok(t) => audit.records = t.records.into_iter().filter(|r| has_version(r, "DMARC1")).collect(),
        Err(e) => audit.lookup_error = Some(e),
    }
    if let [only] = audit.records.as_slice() {
        audit.parsed = Some(parse_dmarc(only));
    }
    audit
}

pub fn parse_dmarc(record: &str) -> DmarcRecord {
    let t = tags(record);
    let get = |k: &str| t.get(k).map(String::as_str).unwrap_or_default();
    let align = |k: &str| if get(k).eq_ignore_ascii_case("s") { Alignment::Strict } else { Alignment::Relaxed };
    let uris = |k: &str| get(k).split(',').filter(|u| !u.is_empty()).map(String::from).collect();
    DmarcRecord {
        policy: Policy::parse(get("p")),
        subdomain_policy: Policy::parse(get("sp")),
        pct: get("pct").parse().ok().filter(|&p| p <= 100).unwrap_or(100),
        rua: uris("rua"),
        ruf: uris("ruf"),
        adkim: align("adkim"),
        aspf: align("aspf"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_record() {
        let d = parse_dmarc(
            "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=r; pct=30; rua=mailto:a@x.test,mailto:b@x.test; ruf=mailto:f@x.test",
        );
        assert_eq!(d.policy, Some(Policy::Reject));
        assert_eq!(d.subdomain_policy, Some(Policy::Quarantine));
        assert_eq!((d.adkim, d.aspf, d.pct), (Alignment::Strict, Alignment::Relaxed, 30));
        assert_eq!(d.rua, ["mailto:a@x.test", "mailto:b@x.test"]);
        assert_eq!(d.ruf, ["mailto:f@x.test"]);
    }

    #[test]
    fn defaults_are_relaxed_alignment_and_all_of_the_mail() {
        let d = parse_dmarc("v=DMARC1; p=none");
        assert_eq!((d.adkim, d.aspf, d.pct, d.subdomain_policy), (Alignment::Relaxed, Alignment::Relaxed, 100, None));
        assert!(d.rua.is_empty() && d.ruf.is_empty());
    }

    #[test]
    fn values_are_case_insensitive_and_whitespace_free() {
        let d = parse_dmarc("V=DMARC1 ; P = Quarantine ; RUA = mailto:a@x.test , mailto:b@x.test ; ADKIM=S");
        assert_eq!(d.policy, Some(Policy::Quarantine));
        assert_eq!(d.rua, ["mailto:a@x.test", "mailto:b@x.test"]);
        assert_eq!(d.adkim, Alignment::Strict);
    }

    #[test]
    fn a_missing_or_unknown_policy_is_none_not_the_none_policy() {
        assert_eq!(parse_dmarc("v=DMARC1; rua=mailto:a@x.test").policy, None);
        assert_eq!(parse_dmarc("v=DMARC1; p=block").policy, None);
        assert_eq!(parse_dmarc("v=DMARC1; p=").policy, None);
    }

    #[test]
    fn pct_outside_0_to_100_or_not_a_number_is_ignored() {
        for bad in ["101", "-1", "abc", "", "1e2", "99999999999999999999", "+50x"] {
            assert_eq!(parse_dmarc(&format!("v=DMARC1; p=none; pct={bad}")).pct, 100, "{bad:?}");
        }
        assert_eq!(parse_dmarc("v=DMARC1; p=none; pct=0").pct, 0);
        assert_eq!(parse_dmarc("v=DMARC1; p=none; pct=+50").pct, 50);
    }

    #[test]
    fn empty_report_addresses_are_dropped() {
        assert_eq!(parse_dmarc("v=DMARC1; p=none; rua=,mailto:a@x.test,,").rua, ["mailto:a@x.test"]);
    }

    #[test]
    fn hostile_records_do_not_panic() {
        for junk in [
            "",
            ";;;",
            "=",
            "v=DMARC1;p",
            &format!("v=DMARC1; rua={}", "a,".repeat(40_000)),
            "p=\u{0}\u{1b}é;sp=\u{85}",
        ] {
            let _ = parse_dmarc(junk);
        }
    }
}
