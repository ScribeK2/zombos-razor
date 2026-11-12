//! The CAA half of the TLS Check: which CAs the domain's CAA records allow to
//! issue (RFC 8659). The lookup climbs the name tree.

use std::{net::SocketAddr, time::Duration};

use hickory_proto::rr::{RData, RecordType};
use serde::Serialize;

use super::{TlsResult, finding};
use crate::{
    email_auth::clip,
    finding::{Finding, Severity},
    resolver::Resolver,
    text::printable,
};

const MAX_RECORDS: usize = 32;
const MAX_LABELS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaaRecord {
    pub critical: bool,
    pub tag: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaaResult {
    /// The name the question was about.
    pub name: String,
    /// The name whose CAA records apply: the question's name or the nearest parent that has any.
    pub found_at: Option<String>,
    pub records: Vec<CaaRecord>,
    /// A question got no usable answer, so the records that apply are unknown.
    pub error: Option<String>,
}

/// Ask for CAA at `name`, then at each parent name, until one has records. A
/// parent is asked up to the top-level domain, not the root.
pub async fn check_caa(resolvers: &[SocketAddr], name: &str, query_timeout: Duration) -> CaaResult {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let mut out = CaaResult { name: name.clone(), found_at: None, records: vec![], error: None };
    let resolver = Resolver::new(resolvers, query_timeout);
    let mut at = name.as_str();
    for _ in 0..MAX_LABELS {
        match resolver.ask(at, RecordType::CAA).await {
            Err(e) => {
                out.error =
                    Some(format!("the CAA question for {} failed: {}", printable(&clip(at)), printable(&clip(&e))));
                return out;
            }
            Ok(m) => {
                out.records = m
                    .answers
                    .iter()
                    .filter_map(|a| match &a.data {
                        RData::CAA(c) => Some(CaaRecord {
                            critical: c.issuer_critical,
                            tag: printable(&clip(&c.tag.to_ascii_lowercase())),
                            value: printable(&clip(&String::from_utf8_lossy(&c.value))),
                        }),
                        _ => None,
                    })
                    .take(MAX_RECORDS)
                    .collect();
                if !out.records.is_empty() {
                    out.found_at = Some(at.to_string());
                    return out;
                }
            }
        }
        match at.split_once('.') {
            Some((_, parent)) if !parent.is_empty() => at = parent,
            _ => return out,
        }
    }
    out
}

/// The CAs a CAA property value names. `None` when no record has the tag; an
/// empty list when every record with it is `";"`, which forbids all issuance.
fn allowed(records: &[CaaRecord], tag: &str) -> Option<Vec<String>> {
    let mut found = false;
    let mut out = vec![];
    for r in records.iter().filter(|r| r.tag == tag) {
        found = true;
        let domain = r.value.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        if !domain.is_empty() && !out.contains(&domain) {
            out.push(domain);
        }
    }
    found.then_some(out)
}

struct KnownCa {
    /// Lower-case fragments of the issuer's common name.
    contains: &'static [&'static str],
    /// Whole common names that are too short to match as a fragment.
    exact: &'static [&'static str],
    /// The CAA identifiers the CA recognises as itself.
    domains: &'static [&'static str],
}

const LETS_ENCRYPT_CNS: &[&str] = &[
    "r3", "r4", "r10", "r11", "r12", "r13", "r14", "e1", "e5", "e6", "e7", "e8", "e9", "ye1", "ye2", "ye3", "yr1",
    "yr2", "yr3",
];
const GOOGLE_CNS: &[&str] = &["wr1", "wr2", "wr3", "wr4", "wr5", "we1", "we2", "we3", "we4"];

const KNOWN_CAS: &[KnownCa] = &[
    KnownCa {
        contains: &["let's encrypt", "letsencrypt", "isrg"],
        exact: LETS_ENCRYPT_CNS,
        domains: &["letsencrypt.org"],
    },
    KnownCa {
        contains: &["digicert", "geotrust", "rapidssl", "thawte", "symantec"],
        exact: &[],
        domains: &["digicert.com", "geotrust.com", "rapidssl.com", "thawte.com", "symantec.com"],
    },
    KnownCa {
        contains: &["sectigo", "comodo", "usertrust", "zerossl"],
        exact: &[],
        domains: &["sectigo.com", "comodoca.com", "usertrust.com", "trust-provider.com", "zerossl.com"],
    },
    KnownCa { contains: &["google trust", "gts "], exact: GOOGLE_CNS, domains: &["pki.goog"] },
    KnownCa {
        contains: &["amazon"],
        exact: &[],
        domains: &["amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"],
    },
    KnownCa { contains: &["globalsign"], exact: &[], domains: &["globalsign.com"] },
    KnownCa {
        contains: &["go daddy", "godaddy", "starfield"],
        exact: &[],
        domains: &["godaddy.com", "starfieldtech.com"],
    },
    KnownCa { contains: &["entrust"], exact: &[], domains: &["entrust.net"] },
    KnownCa { contains: &["ssl.com"], exact: &[], domains: &["ssl.com"] },
    KnownCa { contains: &["buypass"], exact: &[], domains: &["buypass.com"] },
    KnownCa { contains: &["actalis"], exact: &[], domains: &["actalis.it"] },
    KnownCa { contains: &["certum"], exact: &[], domains: &["certum.pl"] },
    KnownCa { contains: &["identrust"], exact: &[], domains: &["identrust.com"] },
    KnownCa { contains: &["trustasia"], exact: &[], domains: &["trustasia.com"] },
    KnownCa { contains: &["swisssign"], exact: &[], domains: &["swisssign.com"] },
];

/// The CAA identifiers of the CA behind an issuer name, or none when the name is not in the table.
pub fn ca_identifiers(issuer: &str) -> Option<&'static [&'static str]> {
    let cn = issuer.to_ascii_lowercase();
    KNOWN_CAS
        .iter()
        .find(|c| c.exact.contains(&cn.as_str()) || c.contains.iter().any(|n| cn.contains(n)))
        .map(|c| c.domains)
}

/// CAA findings, with the served certificate's issuer compared when `tls` is given.
pub fn caa_findings(r: &CaaResult, tls: Option<&TlsResult>) -> Vec<Finding> {
    let name = &r.name;
    if let Some(e) = &r.error {
        return vec![finding(
            "caa_lookup_failed",
            Severity::Warning,
            "CAA lookup failed",
            format!("The CAA records for {name} could not be read: {e}. A CA that cannot read them must not issue."),
            Some("Check that the domain's nameservers answer CAA questions.".into()),
        )];
    }
    let Some(at) = &r.found_at else {
        return vec![finding(
            "caa_none",
            Severity::Info,
            "No CAA record",
            format!(
                "{name} and its parent names have no CAA record, so any certificate authority may issue certificates for it."
            ),
            Some("Add a CAA record naming the CA you use, for example: 0 issue \"letsencrypt.org\".".into()),
        )];
    };
    let place = if at == name { name.clone() } else { format!("{name} (the records are on {at})") };
    let issue = allowed(&r.records, "issue");
    let issuewild = allowed(&r.records, "issuewild");
    let mut out = vec![];

    let leaf = tls.and_then(|t| t.chain.first());
    let wildcard = leaf.is_some_and(|l| l.sans.iter().any(|s| s.starts_with("*.")));
    let (tag, effective) = match (&issuewild, wildcard) {
        (Some(w), true) => ("issuewild", Some(w)),
        _ => ("issue", issue.as_ref()),
    };

    match effective {
        None => out.push(finding(
            "caa_no_issue",
            Severity::Info,
            "CAA does not restrict issuance",
            format!("{place} has CAA records, but none with the {tag} tag, so every CA may issue."),
            Some("Add a CAA issue record naming the CA you use.".into()),
        )),
        Some(list) if list.is_empty() => out.push(finding(
            "caa_forbids_all",
            Severity::Warning,
            "CAA forbids all issuance",
            format!(
                "{place} has a CAA {tag} record with no CA in it, so no CA may issue or renew certificates for it."
            ),
            Some("Name the CA you use in the CAA record before the certificate has to be renewed.".into()),
        )),
        Some(list) => {
            let names = list.join(", ");
            match leaf.map(|l| (l, ca_identifiers(&l.issuer))) {
                Some((l, Some(ids))) if !ids.iter().any(|id| list.iter().any(|a| a == id)) => out.push(finding(
                    "caa_forbids_issuer",
                    Severity::Critical,
                    format!("CAA does not allow {}", clip(&l.issuer)),
                    format!(
                        "The certificate served for {name} was issued by {}, but the CAA {tag} records on {at} allow only {names}. A CA checks CAA when it issues, so renewal from this CA will be refused.",
                        clip(&l.issuer)
                    ),
                    Some("Add the issuing CA to the CAA record, or move to a CA the record allows.".into()),
                )),
                Some((l, None)) => out.push(finding(
                    "caa_issuer_unknown",
                    Severity::Info,
                    "Could not match the issuer to a CAA entry",
                    format!("{place} allows only {names}; the certificate's issuer, {}, is not one this tool can map to a CAA name, so compare them by hand.", clip(&l.issuer)),
                    None,
                )),
                _ => out.push(finding("caa_ok", Severity::Ok, "CAA restricts issuance", format!("Only {names} may issue certificates for {place}."), None)),
            }
        }
    }

    if let Some(list) = &issuewild {
        let msg = if list.is_empty() {
            format!("{place} forbids wildcard certificates.")
        } else {
            format!("{place} allows wildcard certificates only from {}.", list.join(", "))
        };
        out.push(finding("caa_issuewild", Severity::Info, "CAA has a wildcard rule", msg, None));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(tag: &str, value: &str) -> CaaRecord {
        CaaRecord { critical: false, tag: tag.into(), value: value.into() }
    }

    #[test]
    fn values_are_split_from_their_parameters_and_empty_means_forbidden() {
        let r = [
            rec("issue", "LetsEncrypt.org; accounturi=https://x"),
            rec("issue", "digicert.com"),
            rec("issuewild", ";"),
        ];
        assert_eq!(allowed(&r, "issue").unwrap(), ["letsencrypt.org", "digicert.com"]);
        assert_eq!(allowed(&r, "issuewild").unwrap(), Vec::<String>::new());
        assert_eq!(allowed(&r, "iodef"), None);
    }

    #[test]
    fn issuers_map_to_caa_names() {
        assert!(ca_identifiers("R11").unwrap().contains(&"letsencrypt.org"));
        assert!(ca_identifiers("Let's Encrypt Authority X3").unwrap().contains(&"letsencrypt.org"));
        assert!(ca_identifiers("GeoTrust TLS RSA CA G1").unwrap().contains(&"digicert.com"));
        assert!(ca_identifiers("Amazon RSA 2048 M02").unwrap().contains(&"amazon.com"));
        assert_eq!(ca_identifiers("Test Intermediate"), None);
        assert_eq!(ca_identifiers("R"), None);
    }
}
