//! The `dns_*` record Findings of `zombo_core::lookup_findings`, fed from the Propagation answer
//! the DNS section already holds. No second query is sent.

use std::collections::BTreeMap;

use zombo_core::{
    Finding,
    lookup::{LookupResult, Value},
    lookup_findings::lookup_findings,
    propagation::{PropagationResult, Scope, VantageAnswer},
    target::{Kind, Target},
};

/// The record rules apply to a domain or a hostname. An email address is judged by its domain
/// in the Email section, and an IP address has no records to read.
pub fn applies(target: &Target) -> bool {
    matches!(target.kind, Kind::Domain | Kind::Hostname)
}

/// The answer whose records the rules read: the first authoritative nameserver that answered
/// with the AA flag, else the first resolver of the largest group of resolvers that agree.
/// A nameserver without the flag is a forwarder, so it is never the truth.
pub fn source(r: &PropagationResult) -> Option<&VantageAnswer> {
    let usable = |a: &&VantageAnswer| a.error.is_none() && a.rcode.is_some();
    if let Some(truth) = r.nameservers.iter().filter(usable).find(|n| n.authoritative == Some(true)) {
        return Some(truth);
    }
    let mut groups: Vec<(Vec<&VantageAnswer>, _)> = vec![];
    for a in r.resolvers.iter().filter(usable) {
        let key = (a.rcode, &a.answers);
        match groups.iter_mut().find(|(_, k)| *k == key) {
            Some((members, _)) => members.push(a),
            None => groups.push((vec![a], key)),
        }
    }
    // max_by_key keeps the last of equal groups, so reverse to keep the earliest.
    groups.into_iter().rev().max_by_key(|(members, _)| members.len()).and_then(|(members, _)| members.first().copied())
}

fn as_lookup(a: &VantageAnswer) -> Option<LookupResult> {
    let records: BTreeMap<String, Vec<Value>> = a
        .answers
        .iter()
        .map(|(t, texts)| {
            let ttl = a.ttl.get(t).copied().unwrap_or(0);
            (t.clone(), texts.iter().map(|text| Value { text: text.clone(), ttl }).collect())
        })
        .collect();
    Some(LookupResult {
        rcode: a.rcode?,
        authoritative: a.authoritative.unwrap_or(false),
        recursion_available: a.recursion_available.unwrap_or(false),
        records,
        errors: a.failed.iter().map(|t| (t.clone(), "no answer".to_string())).collect(),
    })
}

/// The record Findings for `name`, or none when the rules do not apply: a target that is not
/// a domain or hostname, a run that did not ask every type (`Scope::All`), or no usable answer.
/// `dns_nxdomain` is dropped when `dns_propagation_nxdomain` already says the same.
pub fn record_findings(target: &Target, name: &str, r: &PropagationResult, existing: &[Finding]) -> Vec<Finding> {
    let asked_all = Scope::All.types().iter().all(|t| r.types.contains(&t.to_string()));
    if !applies(target) || !asked_all {
        return vec![];
    }
    let Some(lookup) = source(r).and_then(as_lookup) else { return vec![] };
    let mut out = lookup_findings(name, target.kind == Kind::Domain, &lookup);
    if existing.iter().any(|f| f.code == "dns_propagation_nxdomain") {
        out.retain(|f| f.code != "dns_nxdomain");
    }
    out
}

#[cfg(test)]
mod tests {
    use zombo_core::{
        lookup::Rcode,
        propagation::{Agreement, Vantage},
    };

    use super::*;

    fn target(value: &str, kind: Kind) -> Target {
        Target { value: value.into(), kind }
    }

    fn answer(name: &str, authoritative: bool, rcode: Rcode, records: &[(&str, &[&str])]) -> VantageAnswer {
        let address = "127.0.0.1:53".parse().unwrap();
        VantageAnswer {
            vantage: if authoritative {
                Vantage::nameserver(name, address)
            } else {
                Vantage::resolver(name, "x", address)
            },
            rcode: Some(rcode),
            authoritative: Some(authoritative),
            recursion_available: Some(!authoritative),
            answers: records.iter().map(|(t, v)| (t.to_string(), v.iter().map(|s| s.to_string()).collect())).collect(),
            ttl: BTreeMap::new(),
            failed: vec![],
            soa: None,
            error: None,
        }
    }

    fn result(resolvers: Vec<VantageAnswer>, nameservers: Vec<VantageAnswer>) -> PropagationResult {
        PropagationResult {
            agreement: Agreement::Agree,
            intercepted: false,
            types: Scope::All.types().iter().map(ToString::to_string).collect(),
            resolvers,
            nameservers,
            disagree: vec![],
            ns_disagree: vec![],
            stale: BTreeMap::new(),
        }
    }

    const GOOD: &[(&str, &[&str])] =
        &[("A", &["192.0.2.1"]), ("MX", &["10 mail.example.com."]), ("NS", &["ns1.example.com."])];

    fn codes(f: &[Finding]) -> Vec<&'static str> {
        f.iter().map(|f| f.code).collect()
    }

    #[test]
    fn the_authoritative_answer_is_read_even_when_resolvers_say_otherwise() {
        let r = result(
            vec![answer("Google", false, Rcode::NoError, &[("A", &["198.51.100.9"])]); 3],
            vec![answer("ns1", true, Rcode::NoError, GOOD)],
        );
        assert_eq!(source(&r).map(|a| a.vantage.name.as_str()), Some("ns1"));
        let f = record_findings(&target("example.com", Kind::Domain), "example.com", &r, &[]);
        assert!(codes(&f).contains(&"dns_mx"), "{:?}", codes(&f));
    }

    #[test]
    fn a_nameserver_without_the_flag_is_not_the_truth() {
        let r = result(
            vec![answer("Google", false, Rcode::NoError, GOOD)],
            vec![answer("ns1", false, Rcode::NoError, &[])],
        );
        assert_eq!(source(&r).map(|a| a.vantage.name.as_str()), Some("Google"));
    }

    #[test]
    fn without_a_nameserver_the_first_resolver_of_the_largest_agreeing_group_is_read() {
        let odd = answer("Odd", false, Rcode::NoError, &[("A", &["198.51.100.9"])]);
        let r = result(
            vec![odd, answer("Quad9", false, Rcode::NoError, GOOD), answer("Cloudflare", false, Rcode::NoError, GOOD)],
            vec![],
        );
        assert_eq!(source(&r).map(|a| a.vantage.name.as_str()), Some("Quad9"));
    }

    #[test]
    fn a_resolver_that_did_not_answer_is_never_the_source() {
        let mut dead = answer("Dead", false, Rcode::NoError, GOOD);
        dead.error = Some("no answer".into());
        assert!(source(&result(vec![dead], vec![])).is_none());
    }

    #[test]
    fn a_hostname_gets_no_apex_rules_and_a_domain_does() {
        let r = result(vec![], vec![answer("ns1", true, Rcode::NoError, &[("A", &["192.0.2.1"])])]);
        let domain = record_findings(&target("example.com", Kind::Domain), "example.com", &r, &[]);
        let host = record_findings(&target("www.example.com", Kind::Hostname), "www.example.com", &r, &[]);
        assert!(codes(&domain).contains(&"dns_no_mx") && codes(&domain).contains(&"dns_no_ns"));
        assert_eq!(codes(&host), ["dns_resolves"]);
    }

    #[test]
    fn email_and_ip_targets_get_no_record_findings() {
        let r = result(vec![], vec![answer("ns1", true, Rcode::NoError, GOOD)]);
        for t in [target("a@example.com", Kind::Email), target("192.0.2.1", Kind::Ip)] {
            assert!(record_findings(&t, "example.com", &r, &[]).is_empty(), "{t:?}");
        }
    }

    #[test]
    fn a_run_that_did_not_ask_every_type_gets_none() {
        let mut r = result(vec![], vec![answer("ns1", true, Rcode::NoError, GOOD)]);
        r.types = Scope::Web.types().iter().map(ToString::to_string).collect();
        assert!(record_findings(&target("example.com", Kind::Domain), "example.com", &r, &[]).is_empty());
    }

    #[test]
    fn nxdomain_is_said_once() {
        let r = result(vec![], vec![answer("ns1", true, Rcode::NxDomain, &[])]);
        let t = target("nope.example", Kind::Domain);
        assert_eq!(codes(&record_findings(&t, "nope.example", &r, &[])), ["dns_nxdomain"]);
        let said = Finding::new("dns_propagation_nxdomain", zombo_core::Severity::Warning, "x", String::new());
        assert!(record_findings(&t, "nope.example", &r, &[said]).is_empty());
    }

    #[test]
    fn a_type_that_failed_is_reported_as_a_failed_lookup_not_as_missing() {
        let mut a = answer("ns1", true, Rcode::NoError, &[("NS", &["ns1.example.com."]), ("MX", &["10 m."])]);
        a.failed = vec!["A".into(), "AAAA".into(), "CNAME".into()];
        let r = result(vec![], vec![a]);
        let f = record_findings(&target("example.com", Kind::Domain), "example.com", &r, &[]);
        assert!(codes(&f).contains(&"dns_query_errors") && !codes(&f).contains(&"dns_no_address"), "{:?}", codes(&f));
    }
}
