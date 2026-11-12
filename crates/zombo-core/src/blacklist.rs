//! Blocklist lookup: an IPv4 address, or a domain's mail hosts and the domain
//! itself, against the bundled DNS blocklists. Codes, severities, titles and
//! wording are the Go engine's.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use hickory_proto::rr::{RData, RecordType};
use serde::Serialize;
use tokio::{sync::Semaphore, task::JoinSet, time::Instant};

use crate::{
    Finding, Severity,
    check::{Check, Fact, OnDemand, Outcome},
    email_auth::clip,
    resolver::Resolver,
    text::printable,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectKind {
    Ip,
    Domain,
}

/// One DNS blocklist: a subject is listed when `<subject>.<zone>` has an A record.
#[derive(Debug)]
pub struct Dnsbl {
    pub name: &'static str,
    pub zone: &'static str,
    /// Ip lists are queried by reversed IPv4 octets, domain lists by domain name.
    pub kind: SubjectKind,
    /// Of a listing.
    pub severity: Severity,
    pub delist: &'static str,
    /// Added to a listing's message.
    pub note: &'static str,
}

const fn bl(
    name: &'static str,
    zone: &'static str,
    kind: SubjectKind,
    severity: Severity,
    delist: &'static str,
    note: &'static str,
) -> Dnsbl {
    Dnsbl { name, zone, kind, severity, delist, note }
}

/// Bundled reference data: widely used blocklists.
pub const DNSBLS: [Dnsbl; 10] = {
    use Severity::{Critical, Info, Warning};
    use SubjectKind::{Domain, Ip};
    [
        bl("Spamhaus ZEN", "zen.spamhaus.org", Ip, Critical, "https://check.spamhaus.org/", ""),
        bl(
            "SpamCop",
            "bl.spamcop.net",
            Ip,
            Critical,
            "https://www.spamcop.net/bl.shtml",
            "SpamCop listings expire 24 hours after the last report.",
        ),
        bl(
            "Barracuda",
            "b.barracudacentral.org",
            Ip,
            Critical,
            "https://www.barracudacentral.org/rbl/removal-request",
            "",
        ),
        bl("PSBL", "psbl.surriel.com", Ip, Warning, "https://psbl.org/remove", ""),
        bl("Mailspike", "bl.mailspike.net", Ip, Warning, "https://mailspike.org/iplookup.html", ""),
        bl(
            "UCEPROTECT Level 1",
            "dnsbl-1.uceprotect.net",
            Ip,
            Info,
            "https://www.uceprotect.net/en/rblcheck.php",
            "Few providers block on UCEPROTECT; Level 1 entries expire on their own 7 days after the last spam seen, so the paid express delisting is rarely worth it.",
        ),
        bl("Manitu IX", "ix.dnsbl.manitu.net", Ip, Warning, "https://www.dnsbl.manitu.net/", ""),
        bl("GBUdb Truncate", "truncate.gbudb.net", Ip, Warning, "https://www.gbudb.com/truncate/", ""),
        bl("Spamhaus DBL", "dbl.spamhaus.org", Domain, Critical, "https://check.spamhaus.org/", ""),
        bl("SURBL", "multi.surbl.org", Domain, Warning, "https://surbl.org/surbl-analysis", ""),
    ]
};

const ZEN: &str = "zen.spamhaus.org";

/// Which of Spamhaus ZEN's lists a return code means.
fn zen_list(code: &str) -> Option<&'static str> {
    Some(match code {
        "127.0.0.2" => "SBL",
        "127.0.0.3" => "SBL CSS",
        "127.0.0.4" | "127.0.0.5" | "127.0.0.6" | "127.0.0.7" => "XBL",
        "127.0.0.9" => "SBL DROP",
        "127.0.0.10" | "127.0.0.11" => "PBL",
        _ => return None,
    })
}

pub const MAX_ADDRESSES: usize = 5;
const MAX_MX_HOSTS: usize = 10;
const PARALLEL: usize = 10;
const MAX_CODES: usize = 16;
const MAX_REASON_CHARS: usize = 300;
const MAX_TXT_BYTES: usize = 2048;

/// How long to wait: for one question on one resolver, and for all of them together.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub query_timeout: Duration,
    /// Past this, every list that has not answered is reported unknown.
    pub overall: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options { query_timeout: Duration::from_secs(3), overall: Duration::from_secs(15) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Listed,
    Clean,
    /// The list answered that it will not answer this resolver.
    Refused,
    Unknown,
}

/// One blocklist's answer for one subject.
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub zone: &'static str,
    pub delist: &'static str,
    pub state: State,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub codes: Vec<String>,
    /// The list's TXT record, when listed.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// Why refused or unknown.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

impl Verdict {
    fn new(l: &Dnsbl, state: State) -> Self {
        Verdict { zone: l.zone, delist: l.delist, state, codes: vec![], reason: String::new(), error: String::new() }
    }
    fn unknown(l: &Dnsbl, why: impl Into<String>) -> Self {
        Verdict { error: why.into(), ..Self::new(l, State::Unknown) }
    }
}

/// One IPv4 address or domain checked, with every list's verdict by list name.
#[derive(Debug, Clone, Serialize)]
pub struct Subject {
    pub kind: SubjectKind,
    /// Where it came from: "target", "MX host" or "A record of host".
    pub source: String,
    pub lists: BTreeMap<String, Verdict>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct BlacklistResult {
    /// Keyed by address or domain, so a re-run diffs per subject and list.
    pub subjects: BTreeMap<String, Subject>,
    /// Why the domain's mail host addresses could not be found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolve: Option<String>,
    /// An IPv6 target: not checked.
    pub ipv6: bool,
}

/// `d.c.b.a` for a.b.c.d.
fn reversed(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}")
}

/// Check an IPv4 address, or a domain's mail hosts and the domain itself,
/// against the bundled blocklists, at most ten questions at a time.
pub async fn check_blacklist(resolvers: &[SocketAddr], target: &str, opts: Options) -> BlacklistResult {
    let deadline = Instant::now() + opts.overall;
    let resolver = Resolver::new(resolvers, opts.query_timeout);
    let mut res = BlacklistResult::default();
    match target.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => {
            res.ipv6 = true;
            return res;
        }
        Ok(IpAddr::V4(_)) => {
            res.subjects.insert(
                target.to_string(),
                Subject { kind: SubjectKind::Ip, source: "target".into(), lists: BTreeMap::new() },
            );
        }
        Err(_) => {
            res.subjects.insert(
                target.to_string(),
                Subject { kind: SubjectKind::Domain, source: "target".into(), lists: BTreeMap::new() },
            );
            match mail_addresses(&resolver, target).await {
                Ok(addrs) => {
                    for (ip, source) in addrs {
                        if res.subjects.len() > MAX_ADDRESSES {
                            break;
                        }
                        res.subjects.entry(ip.to_string()).or_insert(Subject {
                            kind: SubjectKind::Ip,
                            source,
                            lists: BTreeMap::new(),
                        });
                    }
                }
                Err(e) => res.resolve = Some(e),
            }
        }
    }

    // Every verdict starts unknown and is overwritten as its answer arrives, so a
    // list that never answers is still reported.
    let gate = Arc::new(Semaphore::new(PARALLEL));
    let mut set = JoinSet::new();
    for (subject, s) in &mut res.subjects {
        for l in DNSBLS.iter().filter(|l| l.kind == s.kind) {
            s.lists.insert(l.name.to_string(), Verdict::unknown(l, "no answer before the deadline"));
            let name = match subject.parse::<Ipv4Addr>() {
                Ok(ip) if s.kind == SubjectKind::Ip => format!("{}.{}", reversed(ip), l.zone),
                _ => format!("{subject}.{}", l.zone),
            };
            let (resolver, gate, subject) = (resolver.clone(), gate.clone(), subject.clone());
            set.spawn(async move {
                let _permit = gate.acquire_owned().await;
                (subject, l.name, query_dnsbl(&resolver, l, &name).await)
            });
        }
    }
    let collect = async {
        while let Some(done) = set.join_next().await {
            if let Ok((subject, list, v)) = done
                && let Some(s) = res.subjects.get_mut(&subject)
            {
                s.lists.insert(list.to_string(), v);
            }
        }
    };
    // Dropping the set on timeout aborts the questions still running.
    let _ = tokio::time::timeout_at(deadline, collect).await;
    res
}

/// A domain's MX hosts (or, with no MX, the domain itself) resolved to IPv4
/// addresses, each with where it came from. A null MX is an error: the domain takes no mail.
async fn mail_addresses(resolver: &Resolver, domain: &str) -> Result<Vec<(Ipv4Addr, String)>, String> {
    let m = resolver.ask(domain, RecordType::MX).await?;
    let mut mxs = vec![];
    for a in &m.answers {
        if let RData::MX(mx) = &a.data {
            if mx.exchange.is_root() {
                return Err("it publishes a null MX: it accepts no mail".into());
            }
            mxs.push((mx.preference, mx.exchange.to_string().trim_end_matches('.').to_string()));
        }
    }
    mxs.sort();
    mxs.dedup();
    mxs.truncate(MAX_MX_HOSTS);
    let (hosts, source) = if mxs.is_empty() {
        (vec![domain.to_string()], "A record of ")
    } else {
        (mxs.into_iter().map(|(_, h)| h).collect(), "MX ")
    };
    let mut set = JoinSet::new();
    for (i, h) in hosts.iter().cloned().enumerate() {
        let resolver = resolver.clone();
        set.spawn(async move { (i, resolver.ask(&h, RecordType::A).await) });
    }
    let mut found: Vec<Vec<Ipv4Addr>> = vec![vec![]; hosts.len()];
    let mut errs: Vec<(usize, String)> = vec![];
    let host = |i: usize| hosts.get(i).map(String::as_str).unwrap_or_default();
    while let Some(Ok((i, r))) = set.join_next().await {
        match r {
            Ok(m) => {
                if let Some(slot) = found.get_mut(i) {
                    *slot = m
                        .answers
                        .iter()
                        .filter_map(|a| if let RData::A(ip) = &a.data { Some(ip.0) } else { None })
                        .collect();
                }
            }
            Err(e) => errs.push((i, format!("{}: {e}", printable(&clip(host(i)))))),
        }
    }
    let out: Vec<(Ipv4Addr, String)> = found
        .iter()
        .enumerate()
        .flat_map(|(i, ips)| ips.iter().map(move |ip| (*ip, i)))
        .map(|(ip, i)| (ip, format!("{source}{}", printable(&clip(host(i))))))
        .collect();
    if out.is_empty() && !errs.is_empty() {
        errs.sort();
        return Err(errs.into_iter().map(|(_, e)| e).collect::<Vec<_>>().join("; "));
    }
    Ok(out)
}

fn is_127_255_255(ip: Ipv4Addr) -> bool {
    ip.octets()[..3] == [127, 255, 255]
}

/// Look a name up on a blocklist. NXDOMAIN (or no A record) is clean; a
/// 127.0.0.0/8 answer is a listing, except 127.255.255.0/24 and 127.0.0.1,
/// which lists (Spamhaus, SURBL) use to refuse the query. A timeout or any
/// other answer leaves the verdict unknown.
async fn query_dnsbl(resolver: &Resolver, l: &Dnsbl, name: &str) -> Verdict {
    let m = match resolver.ask(name, RecordType::A).await {
        Ok(m) => m,
        Err(e) => return Verdict::unknown(l, printable(&clip(&e))),
    };
    let mut v = Verdict::new(l, State::Clean);
    let mut alias = false;
    for a in &m.answers {
        let ip = match &a.data {
            RData::A(ip) => ip.0,
            RData::CNAME(_) => {
                alias = true;
                continue;
            }
            _ => continue,
        };
        if is_127_255_255(ip) || ip == Ipv4Addr::LOCALHOST {
            return Verdict {
                codes: vec![ip.to_string()],
                error: format!("the list refused the query ({ip})"),
                ..Verdict::new(l, State::Refused)
            };
        }
        if ip.octets()[0] != 127 {
            // Some resolvers rewrite NXDOMAIN to an ad or block page.
            return Verdict::unknown(l, format!("unexpected answer {ip}; the resolver may be rewriting answers"));
        }
        v.state = State::Listed;
        if v.codes.len() < MAX_CODES {
            v.codes.push(ip.to_string());
        }
    }
    if v.state == State::Clean && alias {
        // A list publishes addresses, not aliases: an alias with no address says nothing about the subject.
        return Verdict::unknown(l, "answered with an alias and no address");
    }
    if v.state == State::Listed {
        v.codes.sort();
        v.codes.dedup();
        if let Ok(t) = resolver.ask(name, RecordType::TXT).await {
            let txt = t.answers.iter().find_map(|a| if let RData::TXT(t) = &a.data { Some(t) } else { None });
            if let Some(t) = txt {
                let bytes: Vec<u8> = t.txt_data.iter().flat_map(|p| p.iter().copied()).take(MAX_TXT_BYTES).collect();
                let text = String::from_utf8_lossy(&bytes);
                let mut chars = text.chars();
                let head: String = chars.by_ref().take(MAX_REASON_CHARS).collect();
                v.reason = printable(&head) + if chars.next().is_some() { "..." } else { "" };
            }
        }
    }
    v
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn finding(
    code: &'static str,
    severity: Severity,
    title: impl Into<Cow<'static, str>>,
    message: String,
    recommendation: impl Into<Cow<'static, str>>,
) -> Finding {
    Finding { code, severity, title: title.into(), message, recommendation: Some(recommendation.into()) }
}

pub fn blacklist_findings(target: &str, r: &BlacklistResult) -> Vec<Finding> {
    use Severity::*;
    if r.ipv6 {
        return vec![finding(
            "blacklist_ipv6",
            Info,
            "IPv6 not checked",
            format!(
                "DNS blocklist coverage for IPv6 is limited, so {} was not checked. This is not a clean result.",
                printable(&clip(target))
            ),
            "Check the sending IPv4 address instead, or look the address up on the providers' own websites.",
        )];
    }
    let mut out = vec![];
    let (mut addresses, mut answered) = (0, 0);
    let (mut refused, mut unknown) = (BTreeSet::new(), vec![]);
    let mut clean = BTreeSet::new(); // lists that answered for at least one subject
    for (subject, s) in &r.subjects {
        if s.kind == SubjectKind::Ip {
            addresses += 1;
        }
        let about = if s.source == "target" { subject.clone() } else { format!("{subject} ({})", s.source) };
        for l in &DNSBLS {
            let Some(v) = s.lists.get(l.name) else { continue };
            match v.state {
                State::Listed => {
                    answered += 1;
                    let mut msg = format!("{about} is listed on {} ({}, {}", l.name, l.zone, v.codes.join(", "));
                    if l.zone == ZEN {
                        let mut parts: Vec<&str> = vec![];
                        for p in v.codes.iter().filter_map(|c| zen_list(c)) {
                            if !parts.contains(&p) {
                                parts.push(p);
                            }
                        }
                        if !parts.is_empty() {
                            msg += &format!(": {}", parts.join(", "));
                        }
                    }
                    msg += ").";
                    if !v.reason.is_empty() {
                        msg += &format!(" Reason given: {}", v.reason);
                    }
                    if !l.note.is_empty() {
                        msg += &format!(" {}", l.note);
                    }
                    let mut sev = l.severity;
                    if l.zone == ZEN && v.codes.iter().all(|c| zen_list(c) == Some("PBL")) {
                        // PBL is policy, not abuse: the range shouldn't send mail directly.
                        sev = Warning;
                        msg += " PBL lists address ranges that shouldn't send mail directly to other servers; it is not an abuse listing.";
                    }
                    out.push(finding(
                        "blacklist_listed",
                        sev,
                        format!("{subject} listed on {}", l.name),
                        msg,
                        format!("Find and stop the cause (a compromised account, open relay or bulk sending), then request removal at {}.", l.delist),
                    ));
                }
                State::Clean => {
                    answered += 1;
                    clean.insert(l.name);
                }
                State::Refused => {
                    refused.insert(l.name);
                }
                State::Unknown => unknown.push(format!("{} for {subject}", l.name)),
            }
        }
    }
    if r.subjects.len() == 1 && addresses == 0 {
        let msg = match &r.resolve {
            Some(why) => format!(
                "Could not look up {}'s mail hosts ({why}), so only domain blocklists were checked.",
                printable(&clip(target))
            ),
            None => format!(
                "No IPv4 mail host addresses were found for {}, so only domain blocklists were checked.",
                printable(&clip(target))
            ),
        };
        out.push(finding(
            "blacklist_no_addresses",
            Warning,
            "No addresses to check",
            msg,
            "Check the domain's MX and A records, or run this Check on the sending IP directly.",
        ));
    }
    if !refused.is_empty() {
        out.push(finding(
            "blacklist_refused",
            Info,
            "Some blocklists refused to answer",
            format!(
                "{} refused the query, so those results are unknown, not clean. Spamhaus blocks queries that arrive through public resolvers such as 8.8.8.8 or 1.1.1.1.",
                refused.iter().copied().collect::<Vec<_>>().join(", ")
            ),
            "Re-run from a network whose DNS resolver is not a public one, or check the address on the list's own website.",
        ));
    }
    if !unknown.is_empty() {
        out.push(finding(
            "blacklist_unknown",
            if answered == 0 { Warning } else { Info },
            "Some blocklists didn't answer",
            format!("No verdict from {}.", unknown.join(", ")),
            "Re-run; if lists keep timing out, outbound DNS may be filtered on this network.",
        ));
    }
    if answered > 0 && !out.iter().any(|f| f.code == "blacklist_listed") {
        let mut what = plural(addresses, "address", "addresses");
        if addresses < r.subjects.len() {
            what += " and the domain";
        }
        out.push(Finding {
            code: "blacklist_clean",
            severity: Ok,
            title: "Not listed".into(),
            message: format!("Checked {what} against {}; none lists them.", plural(clean.len(), "list", "lists")),
            recommendation: None,
        });
    }
    out
}

/// The Blacklist row: it runs only when the rep asks. It asks this machine's resolver, and uses
/// this module's own limits, not the request's query timeout.
pub static CHECK: Check = Check {
    label: "Blacklist",
    on_demand: Some(OnDemand {
        run_label: "Run blacklist check",
        what: "Asks public blocklists whether the target's address, or a domain and its mail hosts, are listed for spam.",
        // The number of lists is DNSBLS.len(); a test in tests/check_blacklist.rs keeps them equal.
        contacts: "This machine's resolver, which sends 10 questions per address to the blocklist operators' DNS servers (Spamhaus, SpamCop, Barracuda and others). They see the address or domain asked about. Nothing connects to the target.",
        note: None,
    }),
    budget: (Duration::from_secs(25), Duration::from_secs(25)),
    owns: &["blacklist_"],
    blind_spots: &[
        "Lists that are not in the table this Check asks.",
        "Private block lists inside the receiving company.",
        "Whether a listing changes delivery: the receiving server decides.",
        "The sending reputation of the domain's mail history.",
    ],
    ..Check::base(|request| {
        Box::pin(async move {
            let resolvers = request.machine()?;
            Ok(outcome(request.name, &check_blacklist(&resolvers, request.name, Options::default()).await))
        })
    })
};

fn outcome(target: &str, r: &BlacklistResult) -> Outcome {
    let mut facts = vec![];
    let mut details = vec![];
    for (subject, s) in &r.subjects {
        let kind = if s.kind == SubjectKind::Ip { "address" } else { "domain" };
        let listed: Vec<_> = s.lists.iter().filter(|(_, v)| v.state == State::Listed).collect();
        let unsure = s.lists.values().filter(|v| matches!(v.state, State::Refused | State::Unknown)).count();
        let mut line = if listed.is_empty() {
            format!("not listed on any of {} lists", s.lists.len() - unsure)
        } else {
            format!("listed on {} of {} lists", listed.len(), s.lists.len())
        };
        if unsure > 0 {
            line += &format!(", {unsure} gave no verdict");
        }
        facts.push(Fact::new(format!("{subject} ({kind}, {})", s.source), line));
        for (name, v) in &listed {
            let why =
                if v.reason.is_empty() { v.codes.join(", ") } else { format!("{} ({})", v.reason, v.codes.join(", ")) };
            facts.push(Fact::new(format!("Listed on {name}"), why));
        }
        for (name, v) in &s.lists {
            let state = match v.state {
                State::Listed => format!("listed {}", v.codes.join(", ")),
                State::Clean => "not listed".to_string(),
                State::Refused => "refused the query".to_string(),
                State::Unknown => format!("no verdict ({})", v.error),
            };
            details.push(Fact::new(format!("{name} for {subject}"), state));
        }
    }
    if let Some(why) = &r.resolve {
        facts.push(Fact::new("Mail host addresses", why));
    }
    if r.ipv6 {
        facts.push(Fact::new("IPv6", "not checked: the blocklists here list IPv4 addresses"));
    }
    Outcome { findings: blacklist_findings(target, r), facts, details_title: "Every list's answer", details }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listed_address_is_called_out_and_every_list_is_kept_in_the_details() {
        let verdict = |state| Verdict {
            zone: "zen.example",
            delist: "",
            state,
            codes: vec!["127.0.0.2".into()],
            reason: String::new(),
            error: String::new(),
        };
        let mut r = BlacklistResult::default();
        r.subjects.insert(
            "127.0.0.2".into(),
            Subject {
                kind: SubjectKind::Ip,
                source: "target".into(),
                lists: [
                    ("Spamhaus ZEN".to_string(), verdict(State::Listed)),
                    ("SpamCop".to_string(), verdict(State::Clean)),
                ]
                .into(),
            },
        );
        let o = outcome("127.0.0.2", &r);
        let lines = o.records();
        assert!(lines.contains(&"127.0.0.2 (address, target): listed on 1 of 2 lists".to_string()));
        assert!(lines.contains(&"Listed on Spamhaus ZEN: 127.0.0.2".to_string()));
        assert_eq!(o.details.len(), 2);
        assert!(!o.findings.is_empty());
    }

    #[test]
    fn a_domain_with_no_address_says_why_nothing_was_checked() {
        let r = BlacklistResult { resolve: Some("no mail host has an address".into()), ..BlacklistResult::default() };
        assert!(
            outcome("example.com", &r)
                .records()
                .contains(&"Mail host addresses: no mail host has an address".to_string())
        );
    }
}
