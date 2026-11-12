//! Findings: pure functions from an audit to conclusions. Codes, severities,
//! titles and wording are the Go engine's.

use super::{
    Bimi, DkimAudit, DmarcAudit, EffectiveAll, EmailAuthResult, MAX_LOOKUPS, Mechanism, MtaSts, Policy, Qualifier,
    SpfAudit, SpfNode, TlsRpt, spf::LOOKUP_CAP,
};
use std::borrow::Cow;

use crate::{
    Finding, Severity,
    check::{Fact, Outcome},
};

fn finding(
    code: &'static str,
    severity: Severity,
    title: impl Into<Cow<'static, str>>,
    message: String,
    recommendation: Option<&'static str>,
) -> Finding {
    Finding { code, severity, title: title.into(), message, recommendation: recommendation.map(Into::into) }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

pub fn spf_findings(domain: &str, r: &SpfAudit) -> Vec<Finding> {
    use Severity::*;
    if let Some(e) = &r.lookup_error {
        return vec![finding(
            "spf_lookup_failed",
            Warning,
            "SPF lookup failed",
            format!("The TXT lookup for {domain} got no answer ({e}), so its SPF record is unknown."),
            Some("Re-run; if it keeps failing, check the domain's nameservers."),
        )];
    }
    match r.records.len() {
        0 => {
            return vec![finding(
                "spf_missing",
                Warning,
                "No SPF record",
                format!("{domain} publishes no SPF record, so receivers can't tell which servers may send its mail."),
                Some("Publish one TXT record starting v=spf1 listing the domain's senders, ending in ~all or -all."),
            )];
        }
        1 => {}
        n => {
            return vec![finding(
                "spf_multiple",
                Critical,
                "Multiple SPF records",
                format!("{domain} publishes {n} v=spf1 records. That is a permerror: receivers treat SPF as broken."),
                Some("Merge them into a single v=spf1 record."),
            )];
        }
    }
    let mut fs = vec![];
    if r.lookups > MAX_LOOKUPS {
        let at = if r.truncated { format!("more than {LOOKUP_CAP}") } else { r.lookups.to_string() };
        fs.push(finding(
            "spf_too_many_lookups",
            Critical,
            "Too many SPF lookups",
            format!("Evaluating {domain}'s SPF record takes {at} DNS lookups; the limit is 10, past which receivers return permerror."),
            Some("Remove unused includes, or replace includes and a/mx terms with ip4/ip6 ranges."),
        ));
    }
    if !r.errors.is_empty() {
        let errs: Vec<_> = r.errors.iter().map(ToString::to_string).collect();
        fs.push(finding(
            "spf_permerror",
            Critical,
            "SPF record is broken",
            format!("Receivers will return permerror for {domain}: {}.", errs.join("; ")),
            Some("Fix the listed terms; an include must point at a domain with exactly one SPF record."),
        ));
    }
    if !r.failed.is_empty() {
        fs.push(finding(
            "spf_lookup_failed",
            Warning,
            "Some SPF lookups failed",
            format!("These lookups got no answer, so the counts above may be low: {}.", r.failed.join("; ")),
            None,
        ));
    }
    match r.all {
        EffectiveAll::All(Qualifier::Pass) => fs.push(finding(
            "spf_pass_all",
            Critical,
            "SPF allows any sender (+all)",
            format!("{domain}'s SPF record ends in +all, authorising every server on the internet to send as it."),
            Some("Change +all to ~all or -all once the real senders are listed."),
        )),
        EffectiveAll::All(Qualifier::Neutral) => fs.push(finding(
            "spf_neutral_all",
            Warning,
            "SPF is neutral (?all)",
            format!("{domain}'s SPF record ends in ?all, so unlisted senders get no verdict and spoofing isn't discouraged."),
            Some("Change ?all to ~all or -all."),
        )),
        EffectiveAll::Absent => fs.push(finding(
            "spf_no_all",
            Warning,
            "SPF has no all",
            format!("{domain}'s SPF record has no all term, so mail from unlisted senders gets a neutral result."),
            Some("End the record with ~all or -all."),
        )),
        EffectiveAll::All(Qualifier::SoftFail) => fs.push(finding(
            "spf_softfail_all",
            Info,
            "SPF softfails unlisted senders (~all)",
            format!("Mail from servers {domain}'s SPF record doesn't list is marked suspicious, not rejected. Common, and safe while senders are being audited; -all is stricter."),
            None,
        )),
        EffectiveAll::All(Qualifier::Fail) => fs.push(finding("spf_fail_all", Ok, "SPF rejects unlisted senders (-all)", format!("{domain}'s SPF record ends in -all."), None)),
        // Behind a redirect that could not be resolved: nothing to conclude.
        EffectiveAll::Unknown => {}
    }
    fs
}

/// A hosted mail service recognisable from a domain's MX hosts, with the SPF
/// include it documents for its outbound servers.
struct Provider {
    name: &'static str,
    /// An MX host equal to, or ending in "." plus, one of these.
    mx_suffixes: &'static [&'static str],
    include: &'static str,
    title: &'static str,
    recommendation: &'static str,
}

const PROVIDERS: [Provider; 2] = [
    Provider {
        name: "Microsoft 365",
        mx_suffixes: &["mail.protection.outlook.com"],
        include: "spf.protection.outlook.com",
        title: "SPF doesn't include Microsoft 365",
        recommendation: "Add include:spf.protection.outlook.com to the SPF record, before its all term.",
    },
    Provider {
        name: "Google Workspace",
        mx_suffixes: &["google.com", "googlemail.com"],
        include: "_spf.google.com",
        title: "SPF doesn't include Google Workspace",
        recommendation: "Add include:_spf.google.com to the SPF record, before its all term.",
    },
];

/// The domain's mail is hosted by a known provider (from its MX), but its SPF
/// record doesn't include that provider anywhere, so mail sent through it is
/// likely to fail SPF. Silent unless there is exactly one SPF record to judge;
/// other problems with the record are `spf_findings`'.
pub fn spf_missing_provider(domain: &str, mx_hosts: &[String], spf: &SpfAudit) -> Vec<Finding> {
    let (1, None, Some(tree)) = (spf.records.len(), &spf.lookup_error, &spf.tree) else { return vec![] };
    let mut out = vec![];
    for p in &PROVIDERS {
        let mx = mx_hosts.iter().map(|h| h.trim_end_matches('.').to_ascii_lowercase()).find(|h| {
            p.mx_suffixes.iter().any(|s| h == s || h.strip_suffix(s).is_some_and(|rest| rest.ends_with('.')))
        });
        let Some(mx) = mx else { continue };
        if spf_includes(tree, p.include) {
            continue;
        }
        out.push(finding(
            "spf_missing_provider",
            Severity::Warning,
            p.title,
            format!(
                "Mail for {domain} is handled by {name} (MX {mx}), but its SPF record doesn't include {name}'s servers, so mail sent through {name} is likely to fail SPF.",
                name = p.name
            ),
            Some(p.recommendation),
        ));
    }
    out
}

/// Whether the SPF tree reaches `domain` through an include or redirect, at any depth.
fn spf_includes(node: &SpfNode, domain: &str) -> bool {
    node.terms.iter().any(|t| match &t.mechanism {
        Mechanism::Include(v) | Mechanism::Redirect(v) => {
            v.strip_suffix('.').unwrap_or(v).eq_ignore_ascii_case(domain)
                || t.target.as_deref().is_some_and(|n| spf_includes(n, domain))
        }
        _ => false,
    })
}

pub fn dkim_findings(domain: &str, r: &DkimAudit) -> Vec<Finding> {
    use Severity::*;
    // One Finding per code, listing selectors, so a report does not repeat itself.
    let (mut active, mut revoked, mut invalid, mut weak, mut short) = (vec![], vec![], vec![], vec![], vec![]);
    fn add(list: &mut Vec<String>, s: String) {
        if !list.contains(&s) {
            list.push(s);
        }
    }
    for k in &r.keys {
        let sized = format!("{} ({}-bit)", k.selector, k.bits.unwrap_or(0));
        if k.revoked {
            add(&mut revoked, k.selector.clone());
            continue;
        }
        if let Some(e) = &k.error {
            add(&mut invalid, format!("{} ({e})", k.selector));
            continue;
        }
        match k.bits {
            Some(b) if b < 1024 => add(&mut weak, sized),
            Some(b) if b < 2048 => add(&mut short, sized),
            _ => {}
        }
        add(&mut active, k.selector.clone());
    }
    let mut out = vec![];
    if !revoked.is_empty() {
        out.push(finding(
            "dkim_revoked",
            Info,
            "Revoked DKIM key",
            format!("An empty key (p=) means revoked; these selectors can't verify mail: {}.", revoked.join(", ")),
            None,
        ));
    }
    if !invalid.is_empty() {
        out.push(finding(
            "dkim_invalid_key",
            Warning,
            "Unusable DKIM key",
            format!("Receivers can't verify mail signed with these selectors: {}.", invalid.join("; ")),
            Some("Republish the key exactly as the mail provider gives it; long keys are often truncated or mangled when pasted."),
        ));
    }
    if !weak.is_empty() {
        out.push(finding(
            "dkim_weak_key",
            Critical,
            "DKIM key too short",
            format!("RSA keys under 1024 bits are ignored by receivers and can be factored: {}.", weak.join(", ")),
            Some("Rotate to a 2048-bit key with the mail provider."),
        ));
    }
    if !short.is_empty() {
        out.push(finding(
            "dkim_short_key",
            Warning,
            "DKIM key below 2048 bits",
            format!("2048 bits is the current recommendation: {}.", short.join(", ")),
            Some("Rotate to a 2048-bit key when the provider allows it."),
        ));
    }
    if !active.is_empty() {
        out.push(finding(
            "dkim_found",
            Ok,
            "DKIM key published",
            format!("{domain} publishes DKIM keys for {}.", active.join(", ")),
            None,
        ));
        return out;
    }
    let mut msg = format!("None of the {} selectors checked has an active DKIM key for {domain}", r.checked.len());
    if !r.custom.is_empty() {
        msg += &format!(" (including {})", r.custom.join(", "));
    }
    msg += ". A provider may use a selector not on the list.";
    if !r.failed.is_empty() {
        msg += &format!(" {} could not be queried.", plural(r.failed.len(), "selector", "selectors"));
    }
    out.push(finding(
        "dkim_missing",
        Warning,
        "No DKIM key found",
        msg,
        Some("Find the selector in the s= tag of a DKIM-Signature header from a real message and add it under \"Check more DKIM selectors\"; if mail isn't signed, enable DKIM with the provider."),
    ));
    out
}

pub fn dmarc_findings(domain: &str, r: &DmarcAudit) -> Vec<Finding> {
    use Severity::*;
    if let Some(e) = &r.lookup_error {
        return vec![finding(
            "dmarc_lookup_failed",
            Warning,
            "DMARC lookup failed",
            format!("The TXT lookup for _dmarc.{domain} got no answer ({e}), so its DMARC policy is unknown."),
            Some("Re-run; if it keeps failing, check the domain's nameservers."),
        )];
    }
    match r.records.len() {
        0 => {
            return vec![finding(
                "dmarc_missing",
                Warning,
                "No DMARC record",
                format!(
                    "_dmarc.{domain} has no DMARC record, so receivers apply no policy to mail failing SPF and DKIM, and nobody gets reports."
                ),
                Some(
                    "Publish v=DMARC1; p=none; rua=mailto:… to start collecting reports, then tighten to quarantine or reject.",
                ),
            )];
        }
        1 => {}
        n => {
            return vec![finding(
                "dmarc_multiple",
                Warning,
                "Multiple DMARC records",
                format!("_dmarc.{domain} has {n} DMARC records, so receivers ignore DMARC for it entirely."),
                Some("Keep a single v=DMARC1 record."),
            )];
        }
    }
    let Some(d) = &r.parsed else { return vec![] };
    let mut fs = vec![];
    match d.policy {
        Some(Policy::None) => fs.push(finding(
            "dmarc_policy_none",
            Warning,
            "DMARC is monitoring only (p=none)",
            format!("{domain}'s DMARC policy is none: failing mail is delivered as usual, so spoofing is reported but not stopped."),
            Some("Once reports show legitimate mail passing, move to p=quarantine, then p=reject."),
        )),
        Some(Policy::Quarantine) => fs.push(finding(
            "dmarc_enforced",
            Ok,
            "DMARC enforced (p=quarantine)",
            format!("Receivers send failing mail to spam for {domain}."),
            None,
        )),
        Some(Policy::Reject) => {
            fs.push(finding("dmarc_enforced", Ok, "DMARC enforced (p=reject)", format!("Receivers reject failing mail for {domain}."), None))
        }
        None => fs.push(finding(
            "dmarc_invalid_policy",
            Warning,
            "DMARC record has no valid policy",
            format!("_dmarc.{domain} has no valid p= tag (none, quarantine or reject), so receivers may ignore the record."),
            Some("Add p=none, p=quarantine or p=reject."),
        )),
    }
    if d.pct < 100 {
        fs.push(finding(
            "dmarc_partial",
            Info,
            format!("DMARC applies to {}% of mail", d.pct),
            format!(
                "pct={}: the policy is applied to only part of failing mail; the rest gets the next weaker treatment.",
                d.pct
            ),
            None,
        ));
    }
    if d.rua.is_empty() {
        fs.push(finding(
            "dmarc_no_rua",
            Info,
            "No DMARC aggregate reports",
            format!("The DMARC record has no rua= address, so nobody sees which servers send as {domain}."),
            Some("Add rua=mailto:<mailbox> to receive daily aggregate reports."),
        ));
    }
    fs
}

fn scheme_is(uri: &str, schemes: &[&str]) -> bool {
    let uri = uri.to_ascii_lowercase();
    schemes.iter().any(|s| uri.starts_with(s))
}

/// TLS-RPT (RFC 8460). The record is optional: absent is info, malformed is a warning.
pub fn tls_rpt_findings(domain: &str, r: &TlsRpt) -> Vec<Finding> {
    use Severity::*;
    if let Some(e) = &r.lookup_error {
        return vec![finding(
            "email_tlsrpt_lookup_failed",
            Warning,
            "TLS-RPT lookup failed",
            format!(
                "The TXT lookup for _smtp._tls.{domain} got no answer ({e}), so its TLS reporting record is unknown."
            ),
            Some("Re-run; if it keeps failing, check the domain's nameservers."),
        )];
    }
    vec![match r.records.len() {
        0 => finding(
            "email_tlsrpt_missing",
            Info,
            "No TLS-RPT record",
            format!(
                "_smtp._tls.{domain} has no TLS-RPT record, so mail servers that support TLS reporting have nowhere to send reports of failed encrypted delivery to {domain}."
            ),
            Some("Optional. Publish v=TLSRPTv1; rua=mailto:<mailbox> as a TXT record at _smtp._tls.<domain>."),
        ),
        1 if r.rua.is_empty() || !r.rua.iter().all(|u| scheme_is(u, &["mailto:", "https:"])) => finding(
            "email_tlsrpt_invalid",
            Warning,
            "TLS-RPT record is unusable",
            format!(
                "The TLS-RPT record at _smtp._tls.{domain} has no usable rua= (every address must start with mailto: or https:), so senders have nowhere to send reports."
            ),
            Some("Set rua=mailto:<mailbox> or rua=https://<endpoint>."),
        ),
        1 => finding(
            "email_tlsrpt_ok",
            Ok,
            "TLS-RPT published",
            format!("TLS failure reports for {domain} go to {}.", r.rua.join(", ")),
            None,
        ),
        n => finding(
            "email_tlsrpt_multiple",
            Warning,
            "Multiple TLS-RPT records",
            format!("_smtp._tls.{domain} has {n} TLS-RPT records, so senders ignore all of them."),
            Some("Keep a single v=TLSRPTv1 record."),
        ),
    }]
}

/// BIMI. The record is optional: absent is info, malformed is a warning.
pub fn bimi_findings(domain: &str, r: &Bimi) -> Vec<Finding> {
    use Severity::*;
    if let Some(e) = &r.lookup_error {
        return vec![finding(
            "email_bimi_lookup_failed",
            Warning,
            "BIMI lookup failed",
            format!("The TXT lookup for default._bimi.{domain} got no answer ({e}), so its BIMI record is unknown."),
            Some("Re-run; if it keeps failing, check the domain's nameservers."),
        )];
    }
    let invalid = |why: &str| {
        finding(
            "email_bimi_invalid",
            Warning,
            "BIMI record is unusable",
            format!("The BIMI record at default._bimi.{domain} cannot be used: {why}."),
            Some("Set l=https://<host>/logo.svg and, for mail clients that require one, a=https://<host>/vmc.pem."),
        )
    };
    vec![match (r.records.len(), r.logo.as_deref(), r.authority.as_deref()) {
        (0, ..) => finding(
            "email_bimi_missing",
            Info,
            "No BIMI record",
            format!(
                "default._bimi.{domain} has no BIMI record, so mail clients show no brand logo beside mail from {domain}."
            ),
            Some("Optional. BIMI needs DMARC at p=quarantine or p=reject first."),
        ),
        (1, None, _) => invalid("it has no l= tag"),
        (1, Some(l), _) if !l.is_empty() && !scheme_is(l, &["https://"]) => invalid("l= is not an https URL"),
        (1, _, Some(a)) if !a.is_empty() && !scheme_is(a, &["https://"]) => invalid("a= is not an https URL"),
        (1, Some(""), _) => finding(
            "email_bimi_ok",
            Ok,
            "BIMI published",
            format!("{domain}'s BIMI record has an empty l=, which declines to show a logo."),
            None,
        ),
        (1, Some(l), a) => finding(
            "email_bimi_ok",
            Ok,
            "BIMI published",
            match a.filter(|a| !a.is_empty()) {
                Some(a) => format!("{domain} publishes a BIMI logo at {l} with an evidence document at {a}."),
                None => format!(
                    "{domain} publishes a BIMI logo at {l} with no a= evidence document; some mail clients require one."
                ),
            },
            None,
        ),
        (n, ..) => finding(
            "email_bimi_multiple",
            Warning,
            "Multiple BIMI records",
            format!("default._bimi.{domain} has {n} BIMI records, so mail clients ignore all of them."),
            Some("Keep a single v=BIMI1 record."),
        ),
    }]
}

/// The MTA-STS TXT record (RFC 8461). The policy file it points at is not fetched.
pub fn mta_sts_findings(domain: &str, r: &MtaSts) -> Vec<Finding> {
    use Severity::*;
    if let Some(e) = &r.lookup_error {
        return vec![finding(
            "email_mtasts_lookup_failed",
            Warning,
            "MTA-STS lookup failed",
            format!("The TXT lookup for _mta-sts.{domain} got no answer ({e}), so its MTA-STS record is unknown."),
            Some("Re-run; if it keeps failing, check the domain's nameservers."),
        )];
    }
    let valid_id = |id: &str| (1..=32).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric());
    vec![match (r.records.len(), r.id.as_deref()) {
        (0, _) => finding(
            "email_mtasts_missing",
            Info,
            "No MTA-STS record",
            format!(
                "_mta-sts.{domain} has no MTA-STS record, so senders are not told to require TLS when they deliver mail to {domain}."
            ),
            Some(
                "Optional. Publish v=STSv1; id=<version> at _mta-sts.<domain> and serve the policy at https://mta-sts.<domain>/.well-known/mta-sts.txt.",
            ),
        ),
        (1, Some(id)) if valid_id(id) => finding(
            "email_mtasts_ok",
            Ok,
            "MTA-STS record published",
            format!(
                "_mta-sts.{domain} announces an MTA-STS policy (id {id}). Only this record was checked; the policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt was not fetched."
            ),
            None,
        ),
        (1, _) => finding(
            "email_mtasts_invalid",
            Warning,
            "MTA-STS record is unusable",
            format!(
                "The MTA-STS record at _mta-sts.{domain} has no valid id= (1 to 32 letters and digits), so senders ignore it."
            ),
            Some(
                "Set id= to a short alphanumeric version, such as a timestamp, and change it whenever the policy file changes.",
            ),
        ),
        (n, _) => finding(
            "email_mtasts_multiple",
            Warning,
            "Multiple MTA-STS records",
            format!("_mta-sts.{domain} has {n} MTA-STS records, so senders ignore all of them."),
            Some("Keep a single v=STSv1 record."),
        ),
    }]
}

/// Every Finding of one audit.
pub fn email_findings(domain: &str, r: &EmailAuthResult) -> Vec<Finding> {
    let mut fs = spf_findings(domain, &r.spf);
    fs.extend(spf_missing_provider(domain, &r.mx_hosts, &r.spf));
    fs.extend(dkim_findings(domain, &r.dkim));
    fs.extend(dmarc_findings(domain, &r.dmarc));
    fs.extend(tls_rpt_findings(domain, &r.tls_rpt));
    fs.extend(bimi_findings(domain, &r.bimi));
    fs.extend(mta_sts_findings(domain, &r.mta_sts));
    fs
}

/// What the Email row shows: the MX hosts, the SPF and DMARC records and the DKIM keys found, with the Findings.
pub(super) fn outcome(domain: &str, r: &EmailAuthResult) -> Outcome {
    let mut facts: Vec<Fact> = r.mx_hosts.iter().map(|h| Fact::new("MX", h)).collect();
    facts.extend(r.spf.records.iter().map(|s| Fact::new("SPF", s)));
    if r.spf.tree.is_some() {
        facts.push(Fact::new("SPF lookups", format!("{} of {}", r.spf.lookups, MAX_LOOKUPS)));
    }
    facts.extend(r.dmarc.records.iter().map(|s| Fact::new("DMARC", s)));
    let mut details = vec![];
    for k in &r.dkim.keys {
        let bits = k.bits.map(|b| format!(" {b} bits")).unwrap_or_default();
        let revoked = if k.revoked { ", revoked" } else { "" };
        details.push(Fact::new(format!("DKIM {}", k.selector), format!("{}{bits}{revoked}", k.key_type)));
    }
    details.push(Fact::new("DKIM selectors tried", r.dkim.checked.len().to_string()));
    Outcome { findings: email_findings(domain, r), facts, details_title: "DKIM keys", details }
}
