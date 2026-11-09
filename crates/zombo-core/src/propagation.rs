//! DNS Propagation: ask every public resolver for the same records and report
//! where they disagree, i.e. where a change has not reached everyone yet.

use std::{collections::BTreeMap, net::SocketAddr, str::FromStr, time::Duration};

use hickory_proto::rr::RecordType;
use serde::Serialize;
use tokio::task::JoinSet;

use crate::{
    finding::{Finding, Severity},
    lookup::{Rcode, dns_lookup},
};

/// One of the worldwide resolvers DNS Propagation compares.
#[derive(Debug, Clone, Serialize)]
pub struct PublicResolver {
    pub name: String,
    pub location: String,
    pub address: SocketAddr,
}

/// Well-known open resolvers in different regions.
pub fn default_resolvers() -> Vec<PublicResolver> {
    [
        ("Google", "Global anycast", "8.8.8.8"),
        ("Cloudflare", "Global anycast", "1.1.1.1"),
        ("Quad9", "Global anycast", "9.9.9.9"),
        ("OpenDNS", "United States", "208.67.222.222"),
        ("Level3", "United States", "4.2.2.2"),
        ("DNS.SB", "Germany", "185.222.222.222"),
        ("AdGuard", "Cyprus", "94.140.14.14"),
        ("Yandex", "Russia", "77.88.8.8"),
        ("114DNS", "China", "114.114.114.114"),
        ("CleanBrowsing", "Netherlands", "185.228.168.9"),
    ]
    .map(|(n, l, ip)| PublicResolver { name: n.into(), location: l.into(), address: SocketAddr::new(ip.parse().unwrap(), 53) })
    .into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Scope {
    #[default]
    All,
    Mail,
    Web,
}

impl Scope {
    pub fn types(self) -> Vec<RecordType> {
        use RecordType::*;
        match self {
            Scope::All => vec![A, AAAA, CNAME, MX, NS, TXT],
            Scope::Mail => vec![MX, TXT, NS],
            Scope::Web => vec![A, AAAA, CNAME],
        }
    }
}

impl FromStr for Scope {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "all" => Ok(Scope::All),
            "mail" => Ok(Scope::Mail),
            "web" => Ok(Scope::Web),
            _ => Err(format!("scope must be all, mail or web, not {s:?}")),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolverAnswer {
    #[serde(flatten)]
    pub resolver: PublicResolver,
    pub rcode: Option<Rcode>,
    /// Record type -> sorted record texts.
    pub answers: BTreeMap<String, Vec<String>>,
    /// TTL of each answered record type: the smallest across its records.
    pub ttl: BTreeMap<String, u32>,
    /// Types this resolver couldn't answer.
    pub failed: Vec<String>,
    /// Set when the resolver answered nothing at all.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PropagationResult {
    pub types: Vec<String>,
    pub resolvers: Vec<ResolverAnswer>,
    /// Types on which answering resolvers differ, plus "existence" when some
    /// say the name exists and others say NXDOMAIN.
    pub disagree: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PropagationError {
    #[error("none of the public resolvers answered; outbound DNS may be blocked on this network")]
    NoneAnswered,
}

pub async fn propagation(
    resolvers: &[PublicResolver],
    target: &str,
    scope: Scope,
    limit: Duration,
) -> Result<PropagationResult, PropagationError> {
    propagation_with(resolvers, target, scope, limit, |_| {}).await
}

/// Like `propagation`, and calls `on_answer` as each resolver finishes, so a UI
/// can show results while the slowest resolver is still being waited for.
pub async fn propagation_with(
    resolvers: &[PublicResolver],
    target: &str,
    scope: Scope,
    limit: Duration,
    mut on_answer: impl FnMut(&ResolverAnswer),
) -> Result<PropagationResult, PropagationError> {
    let types = scope.types();
    let mut set = JoinSet::new();
    for (i, r) in resolvers.iter().cloned().enumerate() {
        let (target, types) = (target.to_string(), types.clone());
        set.spawn(async move { (i, ask(r, &target, &types, limit).await) });
    }
    let mut slots: Vec<Option<ResolverAnswer>> = vec![None; resolvers.len()];
    while let Some(Ok((i, a))) = set.join_next().await {
        on_answer(&a);
        slots[i] = Some(a);
    }
    let all: Vec<ResolverAnswer> = slots.into_iter().flatten().collect();
    let answered: Vec<&ResolverAnswer> = all.iter().filter(|r| r.error.is_none()).collect();
    if answered.is_empty() {
        return Err(PropagationError::NoneAnswered);
    }

    // Do the answering resolvers (minus any skipped) disagree on `v`?
    let differs = |skip: &dyn Fn(&ResolverAnswer) -> bool, v: &dyn Fn(&ResolverAnswer) -> String| {
        let mut vals = answered.iter().filter(|r| !skip(r)).map(|r| v(r));
        vals.next().is_some_and(|first| vals.any(|x| x != first))
    };
    let mut disagree = vec![];
    if differs(&|_| false, &|r| format!("{:?}", r.rcode)) {
        disagree.push("existence".to_string());
    }
    for t in &types {
        let t = t.to_string();
        if differs(&|r| r.failed.contains(&t), &|r| r.answers.get(&t).map(|v| v.join("\n")).unwrap_or_default()) {
            disagree.push(t);
        }
    }
    Ok(PropagationResult { types: types.iter().map(ToString::to_string).collect(), resolvers: all, disagree })
}

async fn ask(r: PublicResolver, target: &str, types: &[RecordType], limit: Duration) -> ResolverAnswer {
    let mut a = ResolverAnswer {
        resolver: r.clone(),
        rcode: None,
        answers: BTreeMap::new(),
        ttl: BTreeMap::new(),
        failed: vec![],
        error: None,
    };
    // A resolver that answers nothing at all is unreachable, not "no records".
    match dns_lookup(r.address, target, types, limit).await {
        Err(_) => a.error = Some("no answer".into()),
        Ok(l) => {
            a.rcode = Some(l.rcode);
            for t in types {
                let t = t.to_string();
                if l.errors.contains_key(&t) {
                    a.failed.push(t);
                } else if let Some(vals) = l.records.get(&t).filter(|v| !v.is_empty()) {
                    if let Some(min) = vals.iter().map(|v| v.ttl).min() {
                        a.ttl.insert(t.clone(), min);
                    }
                    let mut texts: Vec<String> = vals.iter().map(|v| v.text.clone()).collect();
                    texts.sort();
                    a.answers.insert(t, texts);
                }
            }
        }
    }
    a
}

pub fn propagation_findings(target: &str, r: &PropagationResult) -> Vec<Finding> {
    let mut down = vec![];
    let (mut answered, mut missing) = (0, 0);
    for a in &r.resolvers {
        if a.error.is_some() {
            down.push(a.resolver.name.as_str());
        } else {
            answered += 1;
            if a.rcode == Some(Rcode::NxDomain) {
                missing += 1;
            }
        }
    }
    let mut out = vec![];
    if !down.is_empty() {
        out.push(Finding {
            code: "dns_propagation_unreachable",
            severity: Severity::Info,
            title: "Some resolvers didn't answer",
            message: format!("{} did not respond, so they are left out of the comparison.", down.join(", ")),
            recommendation: None,
        });
    }
    if missing == answered {
        out.push(Finding {
            code: "dns_propagation_nxdomain",
            severity: Severity::Warning,
            title: "Exists on no resolver",
            message: format!("Every resolver that answered says {target} does not exist (NXDOMAIN)."),
            recommendation: Some("Check the spelling and the domain's registration and delegation; there is nothing to propagate yet."),
        });
        return out;
    }
    let (mut records, mut addrs) = (vec![], vec![]);
    for t in &r.disagree {
        match t.as_str() {
            "A" | "AAAA" => addrs.push(t.as_str()),
            "existence" => records.push("whether the name exists"),
            other => records.push(other),
        }
    }
    if !records.is_empty() {
        out.push(Finding {
            code: "dns_propagation_mismatch",
            severity: Severity::Warning,
            title: "Not yet propagated",
            message: format!(
                "Resolvers around the world disagree on {}, so some visitors still see old records.",
                records.join(", ")
            ),
            recommendation: Some("If the records changed recently, wait out the old TTL and re-run; if not, check for a stale or split nameserver."),
        });
    }
    if !addrs.is_empty() {
        out.push(Finding {
            code: "dns_propagation_addresses_vary",
            severity: Severity::Info,
            title: "Addresses vary by region",
            message: format!(
                "{} answers differ between resolvers. That is normal for CDNs and geo-DNS; otherwise the change is still propagating.",
                addrs.join(" and ")
            ),
            recommendation: None,
        });
    }
    if answered < 2 {
        out.push(Finding {
            code: "dns_propagation_insufficient",
            severity: Severity::Warning,
            title: "Too few resolvers answered",
            message: "Only one resolver answered, so there is nothing to compare it with.".into(),
            recommendation: Some("Re-run; if resolvers keep failing, outbound DNS may be filtered on this network."),
        });
    } else if records.is_empty() && addrs.is_empty() {
        out.push(Finding {
            code: "dns_propagation_consistent",
            severity: Severity::Ok,
            title: "Propagated",
            message: format!("All {answered} resolvers that answered agree on {target}."),
            recommendation: None,
        });
    }
    out
}
