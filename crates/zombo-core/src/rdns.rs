//! Reverse DNS and forward-confirmed reverse DNS (FCrDNS). An IP gets its PTR
//! names, each asked forward again; a host or domain gets its addresses.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use hickory_proto::rr::{RData, RecordType};
use serde::Serialize;
use tokio::task::JoinSet;

use crate::{
    Finding, Severity,
    email_auth::{clip, printable},
    resolver::Resolver,
};

const MAX_PTR_NAMES: usize = 8;
const MAX_ADDRESSES: usize = 32;

/// One PTR name of an address, and whether it resolves back to the address.
#[derive(Debug, Clone, Serialize)]
pub struct Ptr {
    pub name: String,
    /// What the name resolves to (A for an IPv4 address, AAAA for an IPv6 one).
    pub addresses: Vec<IpAddr>,
    /// Why the forward lookup got no answer; then `confirmed` says nothing.
    pub forward_error: Option<String>,
    pub confirmed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum RdnsResult {
    Ip {
        ip: IpAddr,
        /// The name the PTR question was asked about.
        ptr_query: String,
        ptr_error: Option<String>,
        ptrs: Vec<Ptr>,
    },
    Host {
        host: String,
        addresses: Vec<IpAddr>,
        /// Which of the A and AAAA questions got no answer.
        errors: Vec<String>,
    },
}

/// The PTR question name: `d.c.b.a.in-addr.arpa.` for a.b.c.d, and the
/// reversed nibbles under `ip6.arpa.` for IPv6.
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa.")
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(73);
            for byte in v6.octets().iter().rev() {
                s += &format!("{:x}.{:x}.", byte & 0xf, byte >> 4);
            }
            s + "ip6.arpa."
        }
    }
}

fn addresses_of(m: &hickory_proto::op::Message, want: RecordType) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = vec![];
    for a in &m.answers {
        let ip = match (&a.data, want) {
            (RData::A(ip), RecordType::A) => IpAddr::V4(ip.0),
            (RData::AAAA(ip), RecordType::AAAA) => IpAddr::V6(ip.0),
            _ => continue,
        };
        if out.len() < MAX_ADDRESSES && !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// Reverse an address and confirm each PTR name forward; or, for a name, list its addresses.
pub async fn check_rdns(resolvers: &[SocketAddr], target: &str, query_timeout: Duration) -> RdnsResult {
    let resolver = Resolver::new(resolvers, query_timeout);
    match target.parse::<IpAddr>() {
        Ok(ip) => check_ip(&resolver, ip).await,
        Err(_) => check_host(&resolver, target).await,
    }
}

async fn check_ip(resolver: &Resolver, ip: IpAddr) -> RdnsResult {
    let ptr_query = reverse_name(ip);
    let mut out = RdnsResult::Ip { ip, ptr_query: ptr_query.clone(), ptr_error: None, ptrs: vec![] };
    let RdnsResult::Ip { ptr_error, ptrs, .. } = &mut out else { return out };
    let m = match resolver.ask(&ptr_query, RecordType::PTR).await {
        Ok(m) => m,
        Err(e) => {
            *ptr_error = Some(e);
            return out;
        }
    };
    let mut names: Vec<String> = vec![];
    for a in &m.answers {
        if let RData::PTR(p) = &a.data {
            let n = p.0.to_string().to_ascii_lowercase();
            if names.len() < MAX_PTR_NAMES && !names.contains(&n) {
                names.push(n);
            }
        }
    }
    let want = if ip.is_ipv4() { RecordType::A } else { RecordType::AAAA };
    let mut set = JoinSet::new();
    for (i, n) in names.iter().cloned().enumerate() {
        let resolver = resolver.clone();
        set.spawn(async move { (i, resolver.ask(&n, want).await) });
    }
    let mut forward: Vec<Option<Result<Vec<IpAddr>, String>>> = vec![None; names.len()];
    while let Some(Ok((i, r))) = set.join_next().await {
        if let Some(slot) = forward.get_mut(i) {
            *slot = Some(r.map(|m| addresses_of(&m, want)));
        }
    }
    for (name, f) in names.into_iter().zip(forward) {
        let name = printable(name.trim_end_matches('.'));
        ptrs.push(match f {
            Some(Ok(addresses)) => Ptr { confirmed: addresses.contains(&ip), name, addresses, forward_error: None },
            Some(Err(e)) => {
                Ptr { name, addresses: vec![], forward_error: Some(printable(&clip(&e))), confirmed: false }
            }
            None => Ptr {
                name,
                addresses: vec![],
                forward_error: Some("the lookup did not finish".into()),
                confirmed: false,
            },
        });
    }
    out
}

async fn check_host(resolver: &Resolver, host: &str) -> RdnsResult {
    let (a, aaaa) = tokio::join!(resolver.ask(host, RecordType::A), resolver.ask(host, RecordType::AAAA));
    let (mut addresses, mut errors) = (vec![], vec![]);
    for (label, want, r) in [("A", RecordType::A, a), ("AAAA", RecordType::AAAA, aaaa)] {
        match r {
            Ok(m) => addresses.extend(addresses_of(&m, want)),
            Err(e) => errors.push(format!("{label}: {}", printable(&clip(&e)))),
        }
    }
    addresses.truncate(MAX_ADDRESSES);
    RdnsResult::Host { host: host.to_string(), addresses, errors }
}

/// The name, lowercased, contains the address's four octets in decimal,
/// separated by the same one of `-`, `.` or `_`, in either order, with no
/// other digit touching either end ("203-0-113-7.dyn.isp.net", "7.113.0.203.example.net").
/// Providers generate such names for addresses nobody has named.
fn embeds_address(name: &str, ip: Ipv4Addr) -> bool {
    let name = name.to_ascii_lowercase();
    let [a, b, c, d] = ip.octets();
    [[a, b, c, d], [d, c, b, a]].iter().any(|seq| {
        ['-', '.', '_'].iter().any(|sep| {
            let needle = seq.iter().map(u8::to_string).collect::<Vec<_>>().join(&sep.to_string());
            name.match_indices(&needle).any(|(i, m)| {
                let digit = |c: Option<char>| c.is_some_and(|c| c.is_ascii_digit());
                !digit(name[..i].chars().next_back()) && !digit(name[i + m.len()..].chars().next())
            })
        })
    })
}

fn finding(
    code: &'static str,
    severity: Severity,
    title: impl Into<std::borrow::Cow<'static, str>>,
    message: String,
    recommendation: Option<&'static str>,
) -> Finding {
    Finding { code, severity, title: title.into(), message, recommendation: recommendation.map(Into::into) }
}

pub fn rdns_findings(r: &RdnsResult) -> Vec<Finding> {
    use Severity::*;
    let mut out = vec![];
    match r {
        RdnsResult::Host { host, addresses, errors } => {
            let host = printable(&clip(host));
            if addresses.is_empty() && !errors.is_empty() {
                out.push(finding(
                    "rdns_lookup_failed",
                    Warning,
                    "Address lookup failed",
                    format!("The address lookup for {host} got no answer ({}).", errors.join("; ")),
                    Some("Re-run; if it keeps failing, check the name's nameservers."),
                ));
            } else if addresses.is_empty() {
                out.push(finding(
                    "rdns_no_address",
                    Warning,
                    "No addresses",
                    format!("{host} has no A or AAAA record, so there is no address to check reverse DNS for."),
                    Some("Publish an A or AAAA record for the name."),
                ));
            } else {
                let list: Vec<String> = addresses.iter().map(ToString::to_string).collect();
                out.push(finding(
                    "rdns_addresses",
                    Info,
                    "Addresses",
                    format!("{host} resolves to {}.", list.join(", ")),
                    None,
                ));
            }
        }
        RdnsResult::Ip { ip, ptr_error, ptrs, .. } => {
            if let Some(e) = ptr_error {
                out.push(finding(
                    "rdns_lookup_failed",
                    Warning,
                    "Reverse DNS lookup failed",
                    format!(
                        "The PTR lookup for {ip} got no answer ({}), so its reverse DNS is unknown.",
                        printable(&clip(e))
                    ),
                    Some("Re-run; if it keeps failing, check the network's DNS resolver."),
                ));
                return out;
            }
            if ptrs.is_empty() {
                out.push(finding(
                    "rdns_no_ptr",
                    Warning,
                    "No reverse DNS",
                    format!("{ip} has no PTR record. Many mail servers reject or down-rank mail from an address without reverse DNS."),
                    Some("Ask whoever owns the address block (the hosting provider or ISP) to set a PTR record naming the mail server's host name, and make that name resolve back to the address."),
                ));
                return out;
            }
            if ptrs.len() > 1 {
                let names: Vec<&str> = ptrs.iter().map(|p| p.name.as_str()).collect();
                out.push(finding(
                    "rdns_multiple_ptr",
                    Info,
                    "Several PTR records",
                    format!("{ip} has {} PTR records ({}). Some receivers look at only one of them, and every name should resolve back to the address.", ptrs.len(), names.join(", ")),
                    Some("Keep one PTR record, the mail server's host name."),
                ));
            }
            for p in ptrs {
                let name = printable(&clip(&p.name));
                if let Some(e) = &p.forward_error {
                    out.push(finding(
                        "rdns_forward_unknown",
                        Info,
                        format!("{name} not confirmed"),
                        format!("The forward lookup of {name}, the PTR name of {ip}, got no answer ({e}), so forward confirmation is unknown."),
                        Some("Re-run; if it keeps failing, check the name's nameservers."),
                    ));
                } else if !p.confirmed {
                    let family = if ip.is_ipv4() { "A" } else { "AAAA" };
                    let got = if p.addresses.is_empty() {
                        format!("has no {family} record")
                    } else {
                        format!(
                            "resolves to {}, not {ip}",
                            p.addresses.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                        )
                    };
                    out.push(finding(
                        "rdns_not_confirmed",
                        Warning,
                        format!("{name} does not resolve back to {ip}"),
                        format!("{ip} points to {name}, which {got}. That fails forward-confirmed reverse DNS (FCrDNS), which mail servers penalise."),
                        Some("Make the PTR name and its A or AAAA record agree: publish an address record for the name that points at this address, or change the PTR record."),
                    ));
                }
                if let IpAddr::V4(v4) = ip
                    && embeds_address(&p.name, *v4)
                {
                    out.push(finding(
                        "rdns_generic_name",
                        Info,
                        format!("{name} looks generated"),
                        format!("The PTR name {name} contains the address {ip} itself, which providers generate for addresses nobody has named. Some mail servers distrust such names."),
                        Some("Ask the provider to set a PTR name under the sending domain, such as mail.example.com."),
                    ));
                }
            }
            if ptrs.iter().all(|p| p.confirmed) {
                let names: BTreeSet<&str> = ptrs.iter().map(|p| p.name.as_str()).collect();
                out.push(finding(
                    "rdns_confirmed",
                    Ok,
                    "Reverse DNS confirmed",
                    format!(
                        "{ip} points to {}, which resolves back to {ip}.",
                        names.into_iter().collect::<Vec<_>>().join(", ")
                    ),
                    None,
                ));
            }
        }
    }
    out
}
