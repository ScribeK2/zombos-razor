//! Delegation and glue: what the parent zone says about a domain, against what
//! the domain's own nameservers say.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{Name, RData, RecordType},
};
use serde::Serialize;

use crate::{
    dns::exchange,
    finding::{Finding, Severity},
    propagation::{DiscoverError, Soa, ask_any, find_apex, ipv6_available},
};

/// Ports to ask on. 53 outside tests.
#[derive(Debug, Clone, Copy)]
pub struct Ports {
    pub parent: u16,
    pub nameserver: u16,
}

impl Default for Ports {
    fn default() -> Self {
        Ports { parent: 53, nameserver: 53 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ServerState {
    /// Answered authoritatively for the zone.
    Ok { serial: u32 },
    /// Did not answer at all.
    Unreachable,
    /// Answered, but not as an authoritative nameserver for the zone.
    Lame { why: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct DelegatedServer {
    pub name: String,
    pub address: Option<SocketAddr>,
    #[serde(flatten)]
    pub state: ServerState,
    /// The NS set this server itself serves for the zone (the child's view).
    pub child_ns: Option<BTreeSet<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DelegationResult {
    pub apex: String,
    pub parent: String,
    /// The NS set the parent delegates to (names lowercased, no trailing dot).
    pub parent_ns: BTreeSet<String>,
    /// Glue addresses the parent's referral carried, by nameserver name.
    pub glue: BTreeMap<String, BTreeSet<IpAddr>>,
    pub servers: Vec<DelegatedServer>,
    /// Addresses of in-zone nameserver names as the zone itself serves them.
    pub glue_served: BTreeMap<String, BTreeSet<IpAddr>>,
    /// Nameserver names that resolve to no address at all.
    pub unresolvable: Vec<String>,
    /// Nameserver names that are aliases, which RFC 2181 forbids.
    pub cnames: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum DelegationError {
    #[error(transparent)]
    Discover(#[from] DiscoverError),
    #[error("{0} is a top-level name: there is no parent zone to compare with")]
    NoParent(String),
    #[error("none of the parent zone's servers returned a delegation for {0}")]
    NoReferral(String),
}

fn norm(n: &Name) -> String {
    n.to_string().trim_end_matches('.').to_lowercase()
}

fn in_zone(name: &str, apex: &str) -> bool {
    name == apex || name.ends_with(&format!(".{apex}"))
}

fn addrs(m: &Message, owner: Option<&str>) -> BTreeSet<IpAddr> {
    m.answers
        .iter()
        .chain(&m.additionals)
        .filter(|r| owner.is_none_or(|o| norm(&r.name) == o))
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect()
}

fn ns_set(m: &Message, apex: &str) -> BTreeSet<String> {
    m.answers
        .iter()
        .chain(&m.authorities)
        .filter(|r| norm(&r.name) == apex)
        .filter_map(|r| match &r.data {
            RData::NS(ns) => Some(norm(&ns.0)),
            _ => None,
        })
        .collect()
}

/// Ask the parent zone's servers for the delegation of `target`'s zone, then ask
/// each delegated nameserver for its own view.
pub async fn check_delegation(
    bootstrap: &[SocketAddr],
    target: &str,
    ports: Ports,
    limit: Duration,
) -> Result<DelegationResult, DelegationError> {
    let (apex, _) = find_apex(bootstrap, target, limit).await?;
    let parent = apex
        .split_once('.')
        .map(|(_, p)| p.to_string())
        .filter(|p| !p.is_empty())
        .ok_or_else(|| DelegationError::NoParent(apex.clone()))?;
    let apex_name = Name::from_ascii(&apex).map_err(|_| DiscoverError::NoNameservers(apex.clone()))?;

    // The parent's servers, as a recursive resolver sees them, then ask one directly
    // (recursion off): its answer is a referral with the glue.
    let parent_name = Name::from_ascii(&parent).map_err(|_| DiscoverError::NoNameservers(parent.clone()))?;
    let parent_servers: Vec<Name> = ask_any(bootstrap, &parent_name, RecordType::NS, limit)
        .await
        .map(|m| {
            m.answers
                .iter()
                .filter_map(|r| match &r.data {
                    RData::NS(ns) => Some(ns.0.clone()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let mut referral: Option<Message> = None;
    'parents: for ps in parent_servers.iter().take(3) {
        let Some(m) = ask_any(bootstrap, ps, RecordType::A, limit).await else { continue };
        for ip in addrs(&m, None) {
            if let Ok(r) = exchange(SocketAddr::new(ip, ports.parent), &apex_name, RecordType::NS, false, limit).await
                && !ns_set(&r, &apex).is_empty()
            {
                referral = Some(r);
                break 'parents;
            }
        }
    }
    let referral = referral.ok_or_else(|| DelegationError::NoReferral(apex.clone()))?;
    let parent_ns = ns_set(&referral, &apex);
    let glue: BTreeMap<String, BTreeSet<IpAddr>> = parent_ns
        .iter()
        .map(|n| (n.clone(), addrs(&referral, Some(n))))
        .filter(|(_, a)| !a.is_empty())
        .collect();

    let (mut servers, mut unresolvable, mut cnames) = (vec![], vec![], vec![]);
    let want_v6 = ipv6_available();
    for ns in parent_ns.iter().take(8) {
        let name = Name::from_ascii(ns).map_err(|_| DiscoverError::NoNameservers(ns.clone()))?;
        let mut ips: BTreeSet<IpAddr> = glue.get(ns).cloned().unwrap_or_default();
        for t in [RecordType::A, RecordType::AAAA] {
            if let Some(m) = ask_any(bootstrap, &name, t, limit).await {
                ips.extend(addrs(&m, None));
                if m.answers.iter().any(|r| matches!(r.data, RData::CNAME(_)) && norm(&r.name) == *ns) {
                    cnames.push(ns.clone());
                }
            }
        }
        // One address is enough to ask; prefer IPv4, and IPv6 only if this machine can use it.
        let pick = ips.iter().find(|i| i.is_ipv4()).or_else(|| ips.iter().find(|i| i.is_ipv6() && want_v6)).copied();
        let Some(ip) = pick else {
            if ips.is_empty() {
                unresolvable.push(ns.clone());
            }
            servers.push(DelegatedServer { name: ns.clone(), address: None, state: ServerState::Unreachable, child_ns: None });
            continue;
        };
        let addr = SocketAddr::new(ip, ports.nameserver);
        let (state, child_ns) = ask_server(addr, &apex_name, &apex, limit).await;
        servers.push(DelegatedServer { name: ns.clone(), address: Some(addr), state, child_ns });
    }

    // What the zone itself says its in-zone nameservers' addresses are.
    let mut glue_served = BTreeMap::new();
    if let Some(addr) = servers.iter().find(|s| matches!(s.state, ServerState::Ok { .. })).and_then(|s| s.address) {
        for ns in parent_ns.iter().filter(|n| in_zone(n, &apex)) {
            let Ok(name) = Name::from_ascii(ns) else { continue };
            let mut set = BTreeSet::new();
            for t in [RecordType::A, RecordType::AAAA] {
                if let Ok(m) = exchange(addr, &name, t, false, limit).await {
                    set.extend(addrs(&m, Some(ns)));
                }
            }
            glue_served.insert(ns.clone(), set);
        }
    }
    Ok(DelegationResult { apex, parent, parent_ns, glue, servers, glue_served, unresolvable, cnames })
}

async fn ask_server(addr: SocketAddr, apex_name: &Name, apex: &str, limit: Duration) -> (ServerState, Option<BTreeSet<String>>) {
    let soa = match exchange(addr, apex_name, RecordType::SOA, false, limit).await {
        Ok(m) => m,
        Err(_) => return (ServerState::Unreachable, None),
    };
    let serial = soa.answers.iter().find_map(|r| match &r.data {
        RData::SOA(_) => Soa::parse(&r.data.to_string()).map(|s| s.serial),
        _ => None,
    });
    let state = match (soa.metadata.response_code, soa.metadata.authoritative, serial) {
        (ResponseCode::NoError, true, Some(serial)) => ServerState::Ok { serial },
        (rc, aa, _) => ServerState::Lame { why: format!("{} (authoritative flag {})", rc.to_str(), if aa { "set" } else { "not set" }) },
    };
    let child_ns = match exchange(addr, apex_name, RecordType::NS, false, limit).await {
        Ok(m) if matches!(state, ServerState::Ok { .. }) => Some(ns_set(&m, apex)),
        _ => None,
    };
    (state, child_ns)
}

pub fn delegation_findings(r: &DelegationResult) -> Vec<Finding> {
    let mut out = vec![];
    let list = |v: &mut dyn Iterator<Item = &String>| v.cloned().collect::<Vec<_>>().join(", ");
    let mut push = |code, severity, title, message: String, recommendation: Option<&'static str>| {
        out.push(Finding { code, severity, title, message, recommendation })
    };

    if r.parent_ns.len() < 2 {
        push(
            "dns_delegation_single_ns",
            Severity::Warning,
            "Only one nameserver",
            format!("{} delegates to {} nameserver, so one outage takes the domain offline.", r.parent, r.parent_ns.len()),
            Some("List at least two nameservers on different networks (RFC 2182)."),
        );
    }
    let down: Vec<&String> = r.servers.iter().filter(|s| s.state == ServerState::Unreachable).map(|s| &s.name).collect();
    if !down.is_empty() {
        push(
            "dns_delegation_unreachable",
            Severity::Warning,
            "A delegated nameserver didn't answer",
            format!("{} did not answer when asked for the zone.", list(&mut down.into_iter())),
            Some("Check that it is online, reachable on UDP and TCP port 53, and that its name has an address."),
        );
    }
    let lame: Vec<String> = r
        .servers
        .iter()
        .filter_map(|s| match &s.state {
            ServerState::Lame { why } => Some(format!("{} ({why})", s.name)),
            _ => None,
        })
        .collect();
    if !lame.is_empty() {
        push(
            "dns_delegation_lame",
            Severity::Critical,
            "Delegated to a server that doesn't serve the zone",
            format!(
                "{} did not answer as an authoritative nameserver for {}. Queries sent to it fail or are answered by something else (a network that intercepts DNS looks the same).",
                lame.join("; "),
                r.apex
            ),
            Some("Remove it from the delegation, or load the zone on that server."),
        );
    }

    // Parent and child disagree about who the nameservers are.
    let (mut only_parent, mut only_child) = (BTreeSet::new(), BTreeSet::new());
    for c in r.servers.iter().filter_map(|s| s.child_ns.as_ref()) {
        only_parent.extend(r.parent_ns.difference(c).cloned());
        only_child.extend(c.difference(&r.parent_ns).cloned());
    }
    if !only_parent.is_empty() || !only_child.is_empty() {
        let mut parts = vec![];
        if !only_parent.is_empty() {
            parts.push(format!("{} only at the parent ({})", list(&mut only_parent.iter()), r.parent));
        }
        if !only_child.is_empty() {
            parts.push(format!("{} only in the zone itself", list(&mut only_child.iter())));
        }
        push(
            "dns_delegation_mismatch",
            Severity::Warning,
            "Parent and zone disagree about the nameservers",
            format!("Nameservers listed {}. Resolvers that cache one side see a different set from those that cache the other.", parts.join(", and ")),
            Some("Make the NS records in the zone match the delegation at the registrar."),
        );
    }

    // Glue: in-zone nameservers need addresses in the parent, and they must be right.
    let (mut missing, mut wrong) = (vec![], vec![]);
    for ns in r.parent_ns.iter().filter(|n| in_zone(n, &r.apex)) {
        match r.glue.get(ns) {
            None => missing.push(ns.clone()),
            Some(g) => {
                let served = r.glue_served.get(ns).filter(|s| !s.is_empty());
                if let Some(s) = served {
                    let fam = |set: &BTreeSet<IpAddr>, v4: bool| set.iter().filter(|i| i.is_ipv4() == v4).copied().collect::<BTreeSet<_>>();
                    // IPv4 always; IPv6 only if the parent gave any (a missing AAAA glue is not a break).
                    if fam(g, true) != fam(s, true) || (!fam(g, false).is_empty() && fam(g, false) != fam(s, false)) {
                        let show = |set: &BTreeSet<IpAddr>| set.iter().map(ToString::to_string).collect::<Vec<_>>().join("/");
                        wrong.push(format!("{ns}: parent says {}, the zone says {}", show(g), show(s)));
                    }
                }
            }
        }
    }
    if !missing.is_empty() {
        push(
            "dns_glue_missing",
            Severity::Critical,
            "Missing glue",
            format!("{} {} inside {} but the parent gave no address for {}, so resolvers cannot find {} (a circular dependency).", list(&mut missing.iter()), if missing.len() == 1 { "is" } else { "are" }, r.apex, if missing.len() == 1 { "it" } else { "them" }, if missing.len() == 1 { "it" } else { "them" }),
            Some("Add glue records for these nameservers at the registrar."),
        );
    }
    if !wrong.is_empty() {
        push(
            "dns_glue_mismatch",
            Severity::Critical,
            "Glue doesn't match the zone",
            format!("The parent's glue differs from the zone's own addresses: {}.", wrong.join("; ")),
            Some("Update the glue at the registrar to the nameserver's current address."),
        );
    }
    if !r.unresolvable.is_empty() {
        push(
            "dns_ns_unresolvable",
            Severity::Critical,
            "A nameserver name doesn't resolve",
            format!("{} has no address, so nothing can reach it.", list(&mut r.unresolvable.iter())),
            Some("Fix the nameserver's host name, or replace it with a working one."),
        );
    }
    if !r.cnames.is_empty() {
        push(
            "dns_ns_is_cname",
            Severity::Critical,
            "A nameserver name is an alias",
            format!("{} is a CNAME, which an NS record must not point at (RFC 2181).", list(&mut r.cnames.iter())),
            Some("Point the NS record at the host's real name."),
        );
    }
    if out.is_empty() {
        out.push(Finding {
            code: "dns_delegation_ok",
            severity: Severity::Ok,
            title: "Delegation is consistent",
            message: format!(
                "{} delegates {} to {} nameservers; the zone lists the same ones, each answers authoritatively, and the glue matches.",
                r.parent,
                r.apex,
                r.parent_ns.len()
            ),
            recommendation: None,
        });
    }
    out
}
