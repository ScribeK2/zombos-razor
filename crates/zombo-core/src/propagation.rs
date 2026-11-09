//! DNS Propagation: ask every public resolver for the same records and report
//! where they disagree, i.e. where a change has not reached everyone yet.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use hickory_proto::rr::{Name, RData, RecordType};
use serde::Serialize;
use tokio::task::JoinSet;

use crate::{
    dns::exchange,
    finding::{Finding, Severity},
    lookup::{Rcode, dns_lookup},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VantageKind {
    /// A public recursive resolver: shows what visitors see, caches included.
    Resolver,
    /// A nameserver the domain's zone is served from, asked directly with
    /// recursion off: shows the truth, with no cache in the way.
    Authoritative,
}

/// Where a Check observes from.
#[derive(Debug, Clone, Serialize)]
pub struct Vantage {
    pub name: String,
    pub location: String,
    pub address: SocketAddr,
    pub kind: VantageKind,
}

impl Vantage {
    pub fn resolver(name: &str, location: &str, address: SocketAddr) -> Self {
        Self { name: name.into(), location: location.into(), address, kind: VantageKind::Resolver }
    }
    pub fn nameserver(name: &str, address: SocketAddr) -> Self {
        Self { name: name.into(), location: "Authoritative".into(), address, kind: VantageKind::Authoritative }
    }
}

/// Well-known open resolvers in different regions.
pub fn default_resolvers() -> Vec<Vantage> {
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
    .map(|(n, l, ip)| Vantage::resolver(n, l, SocketAddr::new(ip.parse().unwrap(), 53)))
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

/// The SOA fields that matter for telling a lagging nameserver from a broken one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Soa {
    pub serial: u32,
    /// Seconds between a secondary's checks for a newer zone.
    pub refresh: u32,
}

impl Soa {
    /// From zone-file form: `mname rname serial refresh retry expire minimum`.
    fn parse(text: &str) -> Option<Self> {
        let mut f = text.split_whitespace().skip(2);
        Some(Soa { serial: f.next()?.parse().ok()?, refresh: f.next()?.parse().ok()? })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VantageAnswer {
    #[serde(flatten)]
    pub vantage: Vantage,
    pub rcode: Option<Rcode>,
    /// Whether the answer carried the authoritative flag; `None` if it didn't answer.
    pub authoritative: Option<bool>,
    /// Record type -> sorted record texts.
    pub answers: BTreeMap<String, Vec<String>>,
    /// TTL of each answered record type: the smallest across its records.
    pub ttl: BTreeMap<String, u32>,
    /// Types this resolver couldn't answer.
    pub failed: Vec<String>,
    /// The zone's SOA, asked of nameservers only.
    pub soa: Option<Soa>,
    /// Set when the Vantage answered nothing at all.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PropagationResult {
    pub types: Vec<String>,
    pub resolvers: Vec<VantageAnswer>,
    pub nameservers: Vec<VantageAnswer>,
    /// Types on which answering resolvers differ, plus "existence" when some
    /// say the name exists and others say NXDOMAIN.
    pub disagree: Vec<String>,
    /// The same, among the authoritative nameservers: the zone is out of sync.
    pub ns_disagree: Vec<String>,
    /// Type (or "existence") -> resolvers whose answer differs from what the
    /// nameservers agree on, i.e. resolvers serving old cached records.
    pub stale: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, thiserror::Error)]
pub enum PropagationError {
    #[error("none of the public resolvers answered; outbound DNS may be blocked on this network")]
    NoneAnswered,
}

pub async fn propagation(
    resolvers: &[Vantage],
    target: &str,
    scope: Scope,
    limit: Duration,
) -> Result<PropagationResult, PropagationError> {
    propagation_with(resolvers, &[], target, scope, limit, |_| {}).await
}

/// Ask every public resolver and every authoritative nameserver for the same
/// records, and compare. Calls `on_answer` as each Vantage finishes, so a UI
/// can show results while the slowest one is still being waited for.
pub async fn propagation_with(
    resolvers: &[Vantage],
    nameservers: &[Vantage],
    target: &str,
    scope: Scope,
    limit: Duration,
    mut on_answer: impl FnMut(&VantageAnswer),
) -> Result<PropagationResult, PropagationError> {
    let types = scope.types();
    let all: Vec<Vantage> = resolvers.iter().chain(nameservers).cloned().collect();
    let mut set = JoinSet::new();
    for (i, v) in all.iter().cloned().enumerate() {
        let target = target.to_string();
        let mut types = types.clone();
        if v.kind == VantageKind::Authoritative {
            types.push(RecordType::SOA); // to tell a lagging nameserver from a broken one
        }
        set.spawn(async move { (i, ask(v, &target, &types, limit).await) });
    }
    let mut slots: Vec<Option<VantageAnswer>> = vec![None; all.len()];
    while let Some(Ok((i, a))) = set.join_next().await {
        on_answer(&a);
        slots[i] = Some(a);
    }
    let mut answers: Vec<VantageAnswer> = slots.into_iter().flatten().collect();
    let ns_answers = answers.split_off(resolvers.len());
    let res_answers = answers;
    let answered = |v: &[VantageAnswer]| v.iter().filter(|a| a.error.is_none()).count();
    if answered(&res_answers) + answered(&ns_answers) == 0 {
        return Err(PropagationError::NoneAnswered);
    }

    let disagree = disagreement(&res_answers, &types);
    let ns_disagree = disagreement(&ns_answers, &types);
    let stale = if ns_disagree.is_empty() { stale(&res_answers, &ns_answers, &types) } else { BTreeMap::new() };
    Ok(PropagationResult {
        types: types.iter().map(ToString::to_string).collect(),
        resolvers: res_answers,
        nameservers: ns_answers,
        disagree,
        ns_disagree,
        stale,
    })
}

/// Types on which the answering Vantages differ, plus "existence" when some
/// say the name exists and others say NXDOMAIN. A type a Vantage failed to
/// query says nothing, so it is skipped.
fn disagreement(all: &[VantageAnswer], types: &[RecordType]) -> Vec<String> {
    let answered: Vec<&VantageAnswer> = all.iter().filter(|r| r.error.is_none()).collect();
    let differs = |skip: &dyn Fn(&VantageAnswer) -> bool, v: &dyn Fn(&VantageAnswer) -> String| {
        let mut vals = answered.iter().filter(|r| !skip(r)).map(|r| v(r));
        vals.next().is_some_and(|first| vals.any(|x| x != first))
    };
    let mut out = vec![];
    if differs(&|_| false, &|r| format!("{:?}", r.rcode)) {
        out.push("existence".to_string());
    }
    for t in types {
        let t = t.to_string();
        if differs(&|r| r.failed.contains(&t), &|r| r.answers.get(&t).map(|v| v.join("\n")).unwrap_or_default()) {
            out.push(t);
        }
    }
    out
}

/// Which resolvers differ from the nameservers, per type. Only nameservers
/// that answered with the authoritative flag count as the truth: an answer
/// without it came from a forwarder or interceptor.
fn stale(resolvers: &[VantageAnswer], nameservers: &[VantageAnswer], types: &[RecordType]) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let Some(truth) = nameservers.iter().find(|n| n.error.is_none() && n.authoritative == Some(true)) else {
        return out;
    };
    let live = resolvers.iter().filter(|r| r.error.is_none());
    for r in live.clone().filter(|r| r.rcode != truth.rcode) {
        out.entry("existence".into()).or_default().push(r.vantage.name.clone());
    }
    for t in types {
        let t = t.to_string();
        if truth.failed.contains(&t) {
            continue;
        }
        let want = truth.answers.get(&t);
        for r in live.clone().filter(|r| r.rcode == truth.rcode && !r.failed.contains(&t) && r.answers.get(&t) != want) {
            out.entry(t.clone()).or_default().push(r.vantage.name.clone());
        }
    }
    out
}

async fn ask(v: Vantage, target: &str, types: &[RecordType], limit: Duration) -> VantageAnswer {
    let mut a = VantageAnswer {
        vantage: v.clone(),
        rcode: None,
        authoritative: None,
        answers: BTreeMap::new(),
        ttl: BTreeMap::new(),
        failed: vec![],
        soa: None,
        error: None,
    };
    // A nameserver is asked directly, so it must not be asked to recurse.
    let recursion = v.kind == VantageKind::Resolver;
    // A Vantage that answers nothing at all is unreachable, not "no records".
    match dns_lookup(v.address, target, types, recursion, limit).await {
        Err(_) => a.error = Some("no answer".into()),
        Ok(l) => {
            a.rcode = Some(l.rcode);
            a.authoritative = Some(l.authoritative);
            a.soa = l.records.get("SOA").and_then(|v| v.first()).and_then(|v| Soa::parse(&v.text));
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

#[derive(Debug, thiserror::Error)]
pub enum DiscoverError {
    #[error("no resolver could be asked for the nameservers of {0}")]
    NoResolver(String),
    #[error("no nameservers found for {0}")]
    NoNameservers(String),
}

/// Find the authoritative nameservers of the zone `target` is in, as Vantages.
///
/// Walks up from the target (never above its registrable domain) until a name
/// has NS records, then resolves each nameserver's addresses. `bootstrap`
/// resolvers are tried in order. `port` is 53 outside tests.
pub async fn discover_nameservers(
    bootstrap: &[SocketAddr],
    target: &str,
    port: u16,
    limit: Duration,
) -> Result<Vec<Vantage>, DiscoverError> {
    // First bootstrap resolver that answers wins.
    let ask_any = |name: Name, t: RecordType| async move {
        for &s in bootstrap {
            if let Ok(m) = exchange(s, &name, t, true, limit).await {
                return Some(m);
            }
        }
        None
    };
    let floor = psl::domain_str(target).unwrap_or(target).to_string();
    let mut zone = target.to_string();
    let ns_names: Vec<String> = loop {
        let name = Name::from_ascii(&zone).map_err(|_| DiscoverError::NoNameservers(target.into()))?;
        let m = ask_any(name, RecordType::NS).await.ok_or_else(|| DiscoverError::NoResolver(target.into()))?;
        let names: Vec<String> = m
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::NS(ns) => Some(ns.0.to_string()),
                _ => None,
            })
            .collect();
        if !names.is_empty() {
            break names;
        }
        match zone.split_once('.') {
            Some((_, parent)) if zone != floor => zone = parent.to_string(),
            _ => return Err(DiscoverError::NoNameservers(target.into())),
        }
    };
    let mut out = vec![];
    for ns in ns_names.iter().take(8) {
        let Ok(name) = Name::from_ascii(ns) else { continue };
        let mut ips = vec![];
        for t in [RecordType::A, RecordType::AAAA] {
            if let Some(m) = ask_any(name.clone(), t).await {
                ips.extend(m.answers.iter().filter_map(|r| match &r.data {
                    RData::A(a) => Some(IpAddr::V4(a.0)),
                    RData::AAAA(a) => Some(IpAddr::V6(a.0)),
                    _ => None,
                }));
            }
        }
        // One address per family is enough to ask: anycast operators list several
        // per nameserver. Skip IPv6 when this machine has no route for it, or
        // every IPv6 nameserver would look down.
        let v4 = ips.iter().find(|ip| ip.is_ipv4());
        let v6 = ips.iter().find(|ip| ip.is_ipv6()).filter(|_| ipv6_available());
        let picked: Vec<&IpAddr> = v4.into_iter().chain(v6).collect();
        let label = ns.trim_end_matches('.');
        for ip in &picked {
            let name = if picked.len() > 1 { format!("{label} {ip}") } else { label.to_string() };
            out.push(Vantage::nameserver(&name, SocketAddr::new(**ip, port)));
        }
    }
    if out.is_empty() {
        return Err(DiscoverError::NoNameservers(target.into()));
    }
    Ok(out)
}

/// Whether this machine has an IPv6 route. Connecting a UDP socket sends nothing;
/// it only fails when there is no route.
fn ipv6_available() -> bool {
    std::net::UdpSocket::bind("[::]:0").and_then(|s| s.connect("[2001:4860:4860::8888]:53")).is_ok()
}

/// The nameservers give different answers. If their SOA serials differ, one is
/// simply behind and will catch up; if the serials are the same, nothing will
/// make it catch up until someone bumps the serial.
fn ns_disagree_finding(r: &PropagationResult) -> Finding {
    let types = r.ns_disagree.join(", ");
    let live: Vec<&VantageAnswer> = r.nameservers.iter().filter(|n| n.error.is_none() && n.authoritative == Some(true)).collect();
    let with_soa: Vec<(&VantageAnswer, Soa)> = live.iter().filter_map(|n| n.soa.map(|s| (*n, s))).collect();
    let low = with_soa.iter().min_by_key(|(_, s)| s.serial);
    let high = with_soa.iter().max_by_key(|(_, s)| s.serial);
    if let (Some((lag, ls)), Some((lead, hs))) = (low, high)
        && ls.serial != hs.serial
    {
        return Finding {
            code: "dns_authoritative_behind",
            severity: Severity::Warning,
            title: "A nameserver is behind",
            message: format!(
                "{} is on SOA serial {} while {} is on {}, so they hold different versions of the zone and visitors get different {types} depending on which one they reach. A nameserver that copies the zone catches up on its next refresh, which this zone sets to every {}.",
                lag.vantage.name, ls.serial, lead.vantage.name, hs.serial, duration(ls.refresh),
            ),
            recommendation: Some("Usually just wait. If it stays behind longer than the refresh interval, check that the zone transfer from the primary works."),
        };
    }
    let same = match low {
        Some((_, s)) => format!(" They report the same serial ({}), so a nameserver that copies the zone will not pick the change up: the serial was not increased.", s.serial),
        None => String::new(),
    };
    Finding {
        code: "dns_authoritative_mismatch",
        severity: Severity::Critical,
        title: "Nameservers are out of sync",
        message: format!("The authoritative nameservers give different answers for {types}, so visitors get different records depending on which one they reach.{same}"),
        recommendation: Some("Make the zone identical on every listed nameserver. If they copy the zone from one primary, increase its SOA serial (re-saving the zone in the DNS panel usually does it); otherwise check that each nameserver was updated."),
    }
}

fn duration(secs: u32) -> String {
    match secs {
        0..=119 => format!("{secs} seconds"),
        120..=7199 => format!("{} minutes", secs.div_ceil(60)),
        _ => format!("{} hours", secs.div_ceil(3600)),
    }
}

pub fn propagation_findings(target: &str, r: &PropagationResult) -> Vec<Finding> {
    let mut out = resolver_findings(target, r);
    out.extend(authoritative_findings(r));
    out
}

fn resolver_findings(target: &str, r: &PropagationResult) -> Vec<Finding> {
    let mut down = vec![];
    let (mut answered, mut missing) = (0, 0);
    for a in &r.resolvers {
        if a.error.is_some() {
            down.push(a.vantage.name.as_str());
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
    if answered == 0 {
        return out;
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

/// What the authoritative nameservers add: whether the zone is healthy, and
/// whether resolvers that differ are just serving cached records.
fn authoritative_findings(r: &PropagationResult) -> Vec<Finding> {
    if r.nameservers.is_empty() {
        return vec![];
    }
    let mut out = vec![];
    let names = |f: &dyn Fn(&VantageAnswer) -> bool| {
        r.nameservers.iter().filter(|n| f(n)).map(|n| n.vantage.name.as_str()).collect::<Vec<_>>().join(", ")
    };
    let down = names(&|n| n.error.is_some());
    if !down.is_empty() {
        out.push(Finding {
            code: "dns_authoritative_unreachable",
            severity: Severity::Warning,
            title: "A nameserver didn't answer",
            message: format!("{down} did not answer when asked directly, so it is left out of the comparison."),
            recommendation: Some("If it should be serving the zone, check that it is online and reachable on UDP and TCP port 53."),
        });
    }
    let faking = names(&|n| n.authoritative == Some(false));
    if !faking.is_empty() {
        out.push(Finding {
            code: "dns_authoritative_not_authoritative",
            severity: Severity::Warning,
            title: "Answer was not authoritative",
            message: format!("{faking} answered without the authoritative flag. A forwarder or a network that intercepts DNS may be answering instead, so its answer is not treated as the truth."),
            recommendation: Some("Re-run from another network, or check that the delegation points at a real nameserver."),
        });
    }
    let live = r.nameservers.iter().filter(|n| n.error.is_none() && n.authoritative == Some(true)).count();
    if live == 0 {
        return out;
    }
    if !r.ns_disagree.is_empty() {
        out.push(ns_disagree_finding(r));
        return out;
    }
    if r.stale.is_empty() {
        if r.resolvers.iter().any(|a| a.error.is_none()) {
            out.push(Finding {
                code: "dns_authoritative_consistent",
                severity: Severity::Ok,
                title: "Matches the authoritative servers",
                message: format!("{live} nameserver(s) agree, and every resolver that answered returns the same records."),
                recommendation: None,
            });
        }
        return out;
    }
    let who: std::collections::BTreeSet<&str> = r.stale.values().flatten().map(String::as_str).collect();
    let types: Vec<&str> = r.stale.keys().map(|t| if t == "existence" { "whether the name exists" } else { t.as_str() }).collect();
    let wait = r
        .resolvers
        .iter()
        .filter(|a| who.contains(a.vantage.name.as_str()))
        .flat_map(|a| r.stale.keys().filter_map(|t| a.ttl.get(t)))
        .max();
    let only_addrs = r.stale.keys().all(|t| t == "A" || t == "AAAA");
    out.push(Finding {
        code: "dns_propagation_stale_cache",
        severity: Severity::Info,
        title: "Some resolvers still serve old records",
        message: format!(
            "The authoritative nameservers agree, but {} of {} resolvers ({}) return something different for {}. {}{}",
            who.len(),
            r.resolvers.iter().filter(|a| a.error.is_none()).count(),
            who.iter().copied().collect::<Vec<_>>().join(", "),
            types.join(", "),
            match wait {
                Some(s) => format!("They are serving cached records and will refresh within {} at the most. ", duration(*s)),
                None => "They are serving cached records. ".into(),
            },
            if only_addrs { "Region-specific (geo-DNS) answers can look the same way." } else { "" },
        ),
        recommendation: Some("Nothing is wrong with the zone. Wait for the cache to expire, or ask the affected visitors to flush their DNS cache."),
    });
    out
}
