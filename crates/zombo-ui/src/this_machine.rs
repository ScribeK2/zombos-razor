//! The "This machine" row of the DNS table: what the resolver in `/etc/resolv.conf` answers.
//!
//! How it takes part. The row is asked the same questions as the ten public resolvers and
//! shown with them, but it is NOT one of them in the verdict. It is never in the
//! `PropagationResult`, so it cannot make the Agreement "Cached" or "Resolvers differ", cannot
//! be the "truth" and cannot be picked as the answer the record Findings read. Instead it is
//! compared with the truth (the authoritative answer, else the first agreeing resolver) and
//! shows Match or Differs. A difference is its own Finding: a router or a network that rewrites
//! answers, split-horizon DNS, or a cache on this network that has not refreshed.

use std::{collections::BTreeMap, net::SocketAddr};

use zombo_core::{
    Finding, Severity,
    propagation::{Vantage, VantageAnswer},
};

pub const NAME: &str = "This machine";

/// The row's own Finding code. `dns_` puts it in the DNS section.
pub const CODE: &str = "dns_this_machine_differs";

const NONE_FOUND: &str = "no nameserver line in /etc/resolv.conf";

/// The first resolver of `/etc/resolv.conf`: a second one is a fallback, so it would answer the
/// same way unless the first is down.
pub fn vantage(servers: &[SocketAddr]) -> Option<Vantage> {
    let first = servers.first()?;
    Some(Vantage::resolver(NAME, &format!("Resolver {}", first.ip()), *first))
}

/// The row when there is nothing to ask: it says why instead of vanishing.
pub fn unavailable() -> VantageAnswer {
    VantageAnswer {
        vantage: Vantage::resolver(NAME, "No resolver found", SocketAddr::from(([0, 0, 0, 0], 0))),
        rcode: None,
        authoritative: None,
        recursion_available: None,
        answers: BTreeMap::new(),
        ttl: BTreeMap::new(),
        failed: vec![],
        soa: None,
        error: Some(NONE_FOUND.into()),
    }
}

/// The types, plus "existence", on which this machine's answer differs from the truth. A type
/// either side failed to query says nothing, so it is skipped.
pub fn differs(truth: &VantageAnswer, local: &VantageAnswer, types: &[String]) -> Vec<String> {
    if local.error.is_some() || truth.error.is_some() {
        return vec![];
    }
    let mut out = vec![];
    if truth.rcode != local.rcode {
        out.push("existence".to_string());
    }
    for t in types {
        if truth.failed.contains(t) || local.failed.contains(t) {
            continue;
        }
        if truth.answers.get(t) != local.answers.get(t) {
            out.push(t.clone());
        }
    }
    out
}

/// The Finding for a difference. Addresses alone differ on a CDN, so that is a note. A
/// difference in anything else (or in whether the name exists) is a warning.
pub fn finding(differing: &[String]) -> Option<Finding> {
    if differing.is_empty() {
        return None;
    }
    let only_addresses = differing.iter().all(|t| t == "A" || t == "AAAA");
    let what: Vec<&str> =
        differing.iter().map(|t| if t == "existence" { "whether the name exists" } else { t.as_str() }).collect();
    Some(Finding {
        code: CODE,
        severity: if only_addresses { Severity::Info } else { Severity::Warning },
        title: "This machine's resolver answers differently".into(),
        message: format!(
            "The resolver this machine uses gives other answers than the authoritative nameservers or the public resolvers for {}. A router or network that rewrites DNS answers, split-horizon DNS, or a cache on this network that has not refreshed would do this.{}",
            what.join(", "),
            if only_addresses { " Differing addresses are also normal for a CDN." } else { "" }
        ),
        recommendation: Some("Compare with the public resolver rows. Visitors outside this network see those, not this machine's answer.".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(rcode: zombo_core::lookup::Rcode, records: &[(&str, &[&str])]) -> VantageAnswer {
        VantageAnswer {
            vantage: Vantage::resolver("x", "y", SocketAddr::from(([127, 0, 0, 1], 53))),
            rcode: Some(rcode),
            authoritative: Some(false),
            recursion_available: Some(true),
            answers: records.iter().map(|(t, v)| (t.to_string(), v.iter().map(|s| s.to_string()).collect())).collect(),
            ttl: BTreeMap::new(),
            failed: vec![],
            soa: None,
            error: None,
        }
    }

    fn types() -> Vec<String> {
        ["A", "AAAA", "CNAME", "MX", "NS", "TXT"].map(String::from).to_vec()
    }

    use zombo_core::lookup::Rcode::{NoError, NxDomain};

    #[test]
    fn the_first_resolv_conf_server_is_asked_and_none_means_no_row_to_ask() {
        let a = SocketAddr::from(([192, 168, 1, 1], 53));
        let b = SocketAddr::from(([192, 168, 1, 2], 53));
        let v = vantage(&[a, b]).unwrap();
        assert_eq!((v.name.as_str(), v.address, v.location.as_str()), (NAME, a, "Resolver 192.168.1.1"));
        assert!(vantage(&[]).is_none());
        let u = unavailable();
        assert_eq!((u.vantage.name.as_str(), u.error.as_deref()), (NAME, Some(NONE_FOUND)));
    }

    #[test]
    fn a_rewritten_answer_differs_and_an_identical_one_does_not() {
        let truth = answer(NoError, &[("A", &["192.0.2.1"]), ("MX", &["10 m."])]);
        assert!(differs(&truth, &truth.clone(), &types()).is_empty());
        let rewritten = answer(NoError, &[("A", &["10.0.0.1"]), ("MX", &["10 m."])]);
        assert_eq!(differs(&truth, &rewritten, &types()), ["A"]);
        let gone = answer(NxDomain, &[]);
        assert_eq!(differs(&truth, &gone, &types())[0], "existence");
    }

    #[test]
    fn a_type_that_failed_or_a_machine_that_did_not_answer_says_nothing() {
        let truth = answer(NoError, &[("A", &["192.0.2.1"])]);
        let mut local = answer(NoError, &[]);
        local.failed = vec!["A".into()];
        assert!(differs(&truth, &local, &types()).iter().all(|t| t != "A"));
        local.error = Some("no answer".into());
        assert!(differs(&truth, &local, &types()).is_empty());
    }

    #[test]
    fn addresses_alone_are_a_note_and_anything_else_a_warning() {
        let sev = |t: &[&str]| finding(&t.iter().map(|s| s.to_string()).collect::<Vec<_>>()).map(|f| f.severity);
        assert_eq!(sev(&["A", "AAAA"]), Some(Severity::Info));
        assert_eq!(sev(&["A", "MX"]), Some(Severity::Warning));
        assert_eq!(sev(&["existence"]), Some(Severity::Warning));
        assert_eq!(sev(&[]), None);
    }
}
