//! Email authentication: SPF, DKIM and DMARC audits and their Findings, plus the
//! DNS-only checks for TLS-RPT, BIMI and the MTA-STS TXT record. All input is
//! untrusted DNS text: nothing here panics on it, and every walk is bounded.

mod dkim;
mod dmarc;
mod findings;
mod query;
mod records;
mod spf;

pub use dkim::{
    DKIM_COMMON_SELECTORS, DkimAudit, DkimFlags, DkimKey, DkimKeyError, KeyType, parse_dkim_key, parse_selectors,
};
pub use dmarc::{Alignment, DmarcAudit, DmarcRecord, Policy, parse_dmarc};
pub use findings::{
    bimi_findings, dkim_findings, dmarc_findings, email_findings, mta_sts_findings, spf_findings, spf_missing_provider,
    tls_rpt_findings,
};
pub use records::{Bimi, MtaSts, TlsRpt, parse_bimi, parse_mta_sts, parse_tls_rpt};
pub use spf::{
    EffectiveAll, HostSpec, MAX_LOOKUPS, Mechanism, NodeError, ParsedSpf, Qualifier, RefKind, SpfAudit, SpfError,
    SpfNode, SpfTerm, effective_all, parse_spf, spf_records,
};

use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

use serde::Serialize;

use crate::{check::Check, target::Kind};
use query::Dns;

/// The Email row: SPF, DKIM, DMARC and the DNS records around them, asked of the first bootstrap
/// resolver. `selectors` are the rep's own DKIM selectors; the request's `query` limits each question.
pub static CHECK: Check = Check {
    label: "Email",
    automatic_for: &[Kind::Domain, Kind::Email],
    budget: (Duration::from_secs(25), Duration::from_secs(4)),
    owns: &["spf_", "dkim_", "dmarc_", "email_"],
    blind_spots: &[
        "Recipient-side filtering: spam filters, quarantine and allow lists decide delivery after DNS passes.",
        "Mail that was really sent: DMARC reports and mail logs hold that, DNS does not.",
        "DKIM keys under a selector this Check did not try.",
        "The settings inside the sending service's own console.",
    ],
    ..Check::base(|request| {
        Box::pin(async move {
            let resolver = request.bootstrap.first().copied().ok_or("no resolver is configured")?;
            let r = email_auth(resolver, request.name, request.selectors, request.query).await;
            if r.answered() {
                Ok(findings::outcome(request.name, &r))
            } else {
                Err(format!("no answer from DNS resolver {resolver}"))
            }
        })
    })
};

/// Everything `email_auth` found for one domain.
#[derive(Debug, Clone, Default, Serialize)]
pub struct EmailAuthResult {
    pub spf: SpfAudit,
    pub dkim: DkimAudit,
    pub dmarc: DmarcAudit,
    pub tls_rpt: TlsRpt,
    pub bimi: Bimi,
    /// The `_mta-sts` TXT record only; the policy file is not fetched.
    pub mta_sts: MtaSts,
    /// The domain's MX hosts, most preferred first: a mail provider shows in them.
    pub mx_hosts: Vec<String>,
}

impl EmailAuthResult {
    /// False when the resolver gave no answer to the SPF, DMARC or any DKIM
    /// question: the other fields then say nothing about the domain.
    pub fn answered(&self) -> bool {
        self.spf.lookup_error.is_none()
            || self.dmarc.lookup_error.is_none()
            || self.dkim.failed.len() < self.dkim.checked.len()
    }
}

/// Audit one domain's email authentication through one resolver. `limit`
/// bounds each DNS question, not the whole audit.
pub async fn email_auth(
    resolver: SocketAddr,
    domain: &str,
    dkim_selectors: &[String],
    limit: Duration,
) -> EmailAuthResult {
    let dns = Dns { server: resolver, limit };
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let (spf, dkim, dmarc, tls_rpt, bimi, mta_sts, mx_hosts) = tokio::join!(
        spf::spf_audit(dns, &domain),
        dkim::dkim_audit(dns, &domain, dkim_selectors),
        dmarc::dmarc_audit(dns, &domain),
        records::tls_rpt_audit(dns, &domain),
        records::bimi_audit(dns, &domain),
        records::mta_sts_audit(dns, &domain),
        dns.mx_hosts(&domain)
    );
    EmailAuthResult { spf, dkim, dmarc, tls_rpt, bimi, mta_sts, mx_hosts: mx_hosts.unwrap_or_default() }
}

/// DKIM and DMARC records are `tag=value; tag=value` lists. Tag names are
/// case-insensitive, whitespace inside a value is dropped, and a repeated tag
/// keeps its last value.
pub(crate) fn tags(record: &str) -> BTreeMap<String, String> {
    record
        .split(';')
        .filter_map(|part| {
            let (k, v) = part.split_once('=')?;
            Some((k.trim().to_ascii_lowercase(), v.split_whitespace().collect()))
        })
        .collect()
}

/// Whether the record's first tag is `v=<version>` (the version is case-insensitive).
pub(crate) fn has_version(record: &str, version: &str) -> bool {
    let first = record.split(';').next().unwrap_or_default();
    first.split_whitespace().collect::<String>().eq_ignore_ascii_case(&format!("v={version}"))
}

/// A hostile token can be 64 KB long; keep the part of it that ends up in a message.
pub(crate) fn clip(s: &str) -> String {
    const MAX: usize = 80;
    match s.char_indices().nth(MAX) {
        Some((i, _)) => format!("{}...", &s[..i]),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_case_insensitive_whitespace_free_and_last_wins() {
        let t = tags("v=DKIM1 ; K = rsa;p=AB CD\n EF;junk;p=XY;;=x");
        assert_eq!(t["k"], "rsa");
        assert_eq!(t["p"], "XY");
        assert_eq!(t["v"], "DKIM1");
        assert_eq!(t[""], "x");
    }

    #[test]
    fn the_version_is_the_first_tag_only() {
        assert!(has_version("v=DMARC1; p=none", "DMARC1"));
        assert!(has_version(" V = dmarc1 ;p=none", "DMARC1"));
        assert!(!has_version("p=none; v=DMARC1", "DMARC1"));
        assert!(!has_version("", "DMARC1"));
    }

    #[test]
    fn clip_cuts_on_a_char_boundary() {
        assert_eq!(clip("short"), "short");
        let long = "é".repeat(200);
        assert_eq!(clip(&long).chars().count(), 83);
    }
}
