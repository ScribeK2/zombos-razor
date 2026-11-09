//! Findings from one DNS Lookup. Codes, severities and wording are the Go engine's
//! `dnsFindings`. Apex rules (MX, NS, CNAME) apply to registrable domains only.

use crate::{
    Finding, Severity,
    lookup::{LookupResult, Rcode},
};

fn finding(
    code: &'static str,
    severity: Severity,
    title: &'static str,
    message: String,
    rec: Option<&'static str>,
) -> Finding {
    Finding { code, severity, title: title.into(), message, recommendation: rec.map(Into::into) }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

pub fn lookup_findings(target: &str, apex: bool, r: &LookupResult) -> Vec<Finding> {
    use Severity::*;
    if r.rcode == Rcode::NxDomain {
        return vec![finding(
            "dns_nxdomain",
            Critical,
            "Name does not exist",
            format!("The resolver answered NXDOMAIN: {target} does not exist in DNS."),
            Some("Check the spelling, then whether the domain is registered and its nameservers are delegated."),
        )];
    }
    let count = |t: &str| r.records.get(t).map_or(0, Vec::len);
    let has = |t: &str| count(t) > 0;
    // A failed query says nothing about whether records exist.
    let known = |types: &[&str]| types.iter().all(|t| !r.errors.contains_key(*t));
    let mut out = vec![];

    if let (true, Some(c)) = (apex, r.records.get("CNAME").and_then(|v| v.first())) {
        out.push(finding(
            "dns_cname_at_apex",
            Critical,
            "CNAME at the zone apex",
            format!(
                "{target} is a CNAME to {}. A CNAME can't coexist with the NS, SOA and MX records the apex needs.",
                c.text
            ),
            Some("Replace it with A/AAAA records, or use the DNS host's ALIAS/flattening feature."),
        ));
    }
    let addrs = count("A") + count("AAAA");
    if addrs > 0 {
        out.push(finding(
            "dns_resolves",
            Ok,
            "Resolves",
            format!("{target} resolves to {}.", plural(addrs, "address", "addresses")),
            None,
        ));
    } else if !has("CNAME") && known(&["A", "AAAA", "CNAME"]) {
        out.push(finding(
            "dns_no_address",
            Warning,
            "No address records",
            format!("{target} has no A or AAAA records, so websites and other services on it can't be reached."),
            Some("Add an A (and ideally AAAA) record pointing at the hosting server, if it should serve anything."),
        ));
    }
    if apex {
        match r.records.get("MX").map(Vec::as_slice).unwrap_or_default() {
            [only] if only.text == "0 ." => out.push(finding(
                "dns_null_mx",
                Info,
                "Declares no mail",
                format!("{target} publishes a null MX (RFC 7505): it accepts no email."),
                None,
            )),
            [] if known(&["MX"]) => out.push(finding(
                "dns_no_mx",
                Warning,
                "No MX records",
                format!("Mail to {target} falls back to its address record, and most senders won't deliver it."),
                Some("Add MX records for the mail provider, or a null MX (0 .) if the domain sends and receives no mail."),
            )),
            [] => {}
            mx => out.push(finding(
                "dns_mx",
                Ok,
                "Mail exchangers set",
                format!("{target} has {}.", plural(mx.len(), "MX record", "MX records")),
                None,
            )),
        }
        if !has("NS") && known(&["NS"]) {
            out.push(finding(
                "dns_no_ns",
                Critical,
                "No NS records",
                format!("The resolver returned no nameservers for {target}."),
                Some("Check the delegation at the registrar and that the zone exists on the listed nameservers."),
            ));
        }
    }
    if !r.errors.is_empty() {
        let types: Vec<&str> = r.errors.keys().map(String::as_str).collect();
        out.push(finding(
            "dns_query_errors",
            Info,
            "Some lookups failed",
            format!(
                "These record types could not be queried, so their absence above is not conclusive: {}.",
                types.join(", ")
            ),
            None,
        ));
    }
    out
}
