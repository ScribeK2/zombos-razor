use std::{net::SocketAddr, time::{Duration, SystemTime}};

use tokio::sync::mpsc::UnboundedSender;
use zombo_core::{
    blacklist::{BlacklistResult, Options as BlacklistOptions, State, SubjectKind, blacklist_findings, check_blacklist},
    delegation::{DelegationResult, Ports, ServerState, check_delegation, delegation_findings},
    dnssec::{DnssecResult, check_dnssec, dnssec_findings, validating_resolvers},
    email_auth::{EmailAuthResult, email_auth, email_findings},
    ports::{PortState, PortsResult, QUICK, Timing as PortTiming, ports_findings, probe, resolve_target},
    propagation::{Scope, default_resolvers, discover_nameservers, propagation_with},
    rdns::{RdnsResult, check_rdns},
    registration::{Endpoints, Registration, check_registration, registration_findings},
    resolver::system_resolvers,
    smtp::{Extensions, Reach, SmtpOptions, SmtpResult, Starttls, check_smtp, smtp_findings},
    target::{Kind, Target},
    tls::{TlsResult, check_tls, tls_findings},
    tls_extras::ocsp_findings,
    web::{WebOptions, WebResult, check_web, parse_web_target, web_findings},
};

use crate::{
    diagnosis::PropEvent,
    outcome::{CheckEvent, Fact, Outcome},
    section::Section,
};

const PER_VANTAGE: Duration = Duration::from_secs(4);
const WHOLE_CHECK: Duration = Duration::from_secs(20);

/// The Checks that run on their own when a target is submitted (DESIGN.md, "Checks per target kind").
pub fn automatic(kind: Kind) -> &'static [Section] {
    use Section::*;
    match kind {
        Kind::Domain | Kind::Email => &[Dns, Delegation, Dnssec, Email, Web, Tls, Registration],
        Kind::Hostname => &[Dns, Web, Tls, Registration],
        Kind::Ip => &[],
    }
}

/// Whether this build has a Check behind the rail section.
pub fn wired(section: Section) -> bool {
    section != Section::Summary
}

/// A Watch re-runs its Check on a timer, so it is offered only where that is harmless.
/// An on-demand Check connects to the target's servers, so it is never watched.
pub fn watchable(section: Section) -> bool {
    wired(section) && !section.is_on_demand()
}

fn limit(section: Section) -> Duration {
    match section {
        Section::Registration => Duration::from_secs(15),
        Section::Email => Duration::from_secs(25),
        Section::Web => Duration::from_secs(12),
        Section::Tls => Duration::from_secs(10),
        Section::Smtp => Duration::from_secs(40),
        Section::Blacklist => Duration::from_secs(25),
        _ => WHOLE_CHECK,
    }
}

pub fn check_name(target: &Target) -> Option<String> {
    match target.kind {
        Kind::Domain | Kind::Hostname => Some(target.value.clone()),
        Kind::Email => target.value.split_once('@').map(|(_, d)| d.to_string()),
        Kind::Ip => None,
    }
}

/// The name an on-demand Check connects to or asks about. An IP address is a valid subject
/// here, unlike for the automatic Checks.
pub fn name_for(section: Section, target: &Target) -> Option<String> {
    if section.is_on_demand() && target.kind == Kind::Ip { Some(target.value.clone()) } else { check_name(target) }
}

pub async fn run_propagation(target: String, tx: UnboundedSender<PropEvent>) {
    let _ = tx.send(PropEvent::Started);
    let work = async {
        let resolvers = default_resolvers();
        let bootstrap: Vec<SocketAddr> = resolvers.iter().map(|r| r.address).collect();
        let nameservers = discover_nameservers(&bootstrap, &target, 53, PER_VANTAGE).await.unwrap_or_default();
        propagation_with(&resolvers, &nameservers, &target, Scope::All, PER_VANTAGE, |a| {
            let _ = tx.send(PropEvent::Answer(Box::new(a.clone())));
        })
        .await
        .map_err(|e| e.to_string())
    };
    let event = match tokio::time::timeout(WHOLE_CHECK, work).await {
        Ok(result) => PropEvent::Finished(Box::new(result)),
        Err(_) => PropEvent::TimedOut,
    };
    let _ = tx.send(event);
}

pub async fn run_section(section: Section, name: String, tx: UnboundedSender<CheckEvent>) {
    let _ = tx.send(CheckEvent::Started);
    let event = match tokio::time::timeout(limit(section), produce(section, &name)).await {
        Ok(result) => CheckEvent::Finished(Box::new(result)),
        Err(_) => CheckEvent::TimedOut,
    };
    let _ = tx.send(event);
}

async fn produce(section: Section, name: &str) -> Result<Outcome, String> {
    let bootstrap: Vec<SocketAddr> = default_resolvers().iter().map(|r| r.address).collect();
    match section {
        Section::Delegation => check_delegation(&bootstrap, name, Ports::default(), PER_VANTAGE)
            .await
            .map(|r| delegation_outcome(&r))
            .map_err(|e| e.to_string()),
        Section::Dnssec => check_dnssec(&bootstrap, &validating_resolvers(), name, 53, SystemTime::now(), PER_VANTAGE)
            .await
            .map(|r| dnssec_outcome(&r))
            .map_err(|e| e.to_string()),
        Section::Email => {
            let resolver = bootstrap.first().copied().ok_or("no resolver is configured")?;
            let r = email_auth(resolver, name, &[], PER_VANTAGE).await;
            if r.answered() { Ok(email_outcome(name, &r)) } else { Err(format!("no answer from DNS resolver {resolver}")) }
        }
        Section::Web => {
            let (host, path) = parse_web_target(name).map_err(|e| e.to_string())?;
            let opts = WebOptions { timeout: Duration::from_secs(10), ..WebOptions::default() };
            Ok(web_outcome(&host, &check_web(&host, &path, &opts).await))
        }
        Section::Tls => check_tls(name, 443, Duration::from_secs(8)).await.map(|r| tls_outcome(name, &r)).map_err(|e| e.to_string()),
        Section::Registration => check_registration(name, &Endpoints::default(), Duration::from_secs(12))
            .await
            .map(|r| registration_outcome(name, &r))
            .map_err(|e| e.to_string()),
        Section::Ports => {
            let addresses = resolve_target(name, Duration::from_secs(4)).await.map_err(|e| e.to_string())?;
            Ok(ports_outcome(name, &probe(&addresses, QUICK, PortTiming::default()).await))
        }
        Section::Smtp => {
            let r = check_smtp(name, 25, &SmtpOptions::for_port(25)).await;
            let mut expect = vec![];
            if name.parse::<std::net::IpAddr>().is_err() {
                expect.push(name.to_string());
            }
            let resolvers = system_resolvers();
            if let (Some(ip), Reach::Answered, false) = (r.peer, r.reach, resolvers.is_empty())
                && let RdnsResult::Ip { ptrs, .. } = check_rdns(&resolvers, &ip.to_string(), Duration::from_secs(3)).await
            {
                expect.extend(ptrs.into_iter().map(|p| p.name));
            }
            Ok(smtp_outcome(&r, &expect))
        }
        Section::Blacklist => {
            let resolvers = system_resolvers();
            if resolvers.is_empty() {
                return Err("this machine has no DNS resolver configured".into());
            }
            Ok(blacklist_outcome(name, &check_blacklist(&resolvers, name, BlacklistOptions::default()).await))
        }
        other => Err(format!("{} has no Check behind it", other.label())),
    }
}

fn addresses(set: &std::collections::BTreeSet<std::net::IpAddr>) -> String {
    set.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")
}

pub fn delegation_outcome(r: &DelegationResult) -> Outcome {
    let mut facts = vec![Fact::new("Zone", &r.apex), Fact::new("Parent zone", &r.parent)];
    facts.extend(r.parent_ns.iter().map(|n| Fact::new("Delegated nameserver", n)));
    for (name, set) in &r.glue {
        facts.push(Fact::new(format!("Glue {name}"), addresses(set)));
    }
    for s in &r.servers {
        let state = match &s.state {
            ServerState::Ok { serial } => format!("answers, SOA serial {serial}"),
            ServerState::Unreachable => "unreachable".to_string(),
            ServerState::Lame { why, .. } => format!("lame: {why}"),
        };
        facts.push(Fact::new(format!("Server {}", s.name), state));
    }
    Outcome { findings: delegation_findings(r), facts, ..Outcome::default() }
}

pub fn dnssec_outcome(r: &DnssecResult) -> Outcome {
    let mut facts = vec![Fact::new("Zone", &r.apex)];
    facts.extend(r.resolvers.iter().map(|v| Fact::new(format!("Resolver {}", v.resolver), v.status.label())));
    for d in &r.ds {
        let matched = if d.matched { "matches a served key" } else { "matches no served key" };
        facts.push(Fact::new("DS record", format!("key tag {}, {}, {}", d.ds.key_tag.0, d.ds.algorithm, matched)));
    }
    let mut details = vec![];
    for n in &r.nameservers {
        match &n.error {
            Some(e) => details.push(Fact::new(format!("Nameserver {}", n.name), format!("no usable answer: {e}"))),
            None => {
                for k in &n.dnskeys {
                    details.push(Fact::new(format!("Key at {}", n.name), format!("key tag {}, {}, flags {}", k.key_tag.0, k.algorithm, k.flags)));
                }
            }
        }
    }
    Outcome { findings: dnssec_findings(r), facts, details_title: "Keys by nameserver", details }
}

pub fn email_outcome(domain: &str, r: &EmailAuthResult) -> Outcome {
    let mut facts: Vec<Fact> = r.mx_hosts.iter().map(|h| Fact::new("MX", h)).collect();
    facts.extend(r.spf.records.iter().map(|s| Fact::new("SPF", s)));
    if r.spf.tree.is_some() {
        facts.push(Fact::new("SPF lookups", format!("{} of {}", r.spf.lookups, zombo_core::email_auth::MAX_LOOKUPS)));
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

pub fn web_outcome(host: &str, r: &WebResult) -> Outcome {
    let mut facts = vec![Fact::new("URL", &r.url)];
    if let Some(u) = &r.final_url {
        facts.push(Fact::new("Final URL", u));
    }
    if let Some(s) = r.status {
        facts.push(Fact::new("Status", s.to_string()));
    }
    if let Some(s) = &r.server {
        facts.push(Fact::new("Server", s));
    }
    if let Some(e) = &r.https_error {
        facts.push(Fact::new("HTTPS error", e));
    }
    let details = r
        .chain
        .iter()
        .enumerate()
        .map(|(i, h)| Fact::new(format!("Hop {}", i + 1), format!("{} {}{}", h.status, h.url, h.location.as_ref().map(|l| format!(" to {l}")).unwrap_or_default())))
        .collect();
    Outcome { findings: web_findings(host, r), facts, details_title: "Redirect chain", details }
}

pub fn tls_outcome(host: &str, r: &TlsResult) -> Outcome {
    let mut facts = vec![
        Fact::new("Protocol", &r.version),
        Fact::new("Cipher", &r.cipher),
        Fact::new("Trust", format!("{:?}", r.trust)),
        Fact::new("Name matches", if r.hostname_match { "yes" } else { "no" }),
    ];
    if let Some(leaf) = r.chain.first() {
        facts.push(Fact::new("Subject", &leaf.subject));
        facts.push(Fact::new("Issuer", &leaf.issuer));
        facts.push(Fact::new("Expires", leaf.not_after.to_string()));
    }
    let details = r.chain.iter().enumerate().map(|(i, c)| Fact::new(format!("Certificate {}", i + 1), format!("{} issued by {}, {}", c.subject, c.issuer, c.key))).collect();
    let mut findings = tls_findings(host, 443, r);
    findings.extend(ocsp_findings(host, 443, r));
    Outcome { findings, facts, details_title: "Certificate chain", details }
}

pub fn registration_outcome(target: &str, r: &Registration) -> Outcome {
    let mut facts = vec![Fact::new("Domain", &r.domain), Fact::new("Registered", if r.registered { "yes" } else { "no" })];
    if let Some(v) = &r.registrar {
        facts.push(Fact::new("Registrar", v));
    }
    for (k, d) in [("Created", &r.created), ("Updated", &r.updated), ("Expires", &r.expires)] {
        if let Some(d) = d {
            facts.push(Fact::new(k, d.to_string()));
        }
    }
    facts.extend(r.statuses.iter().map(|s| Fact::new("Status", s)));
    facts.extend(r.nameservers.iter().map(|n| Fact::new("Nameserver", n)));
    if let Some(d) = r.dnssec {
        facts.push(Fact::new("DNSSEC", if d { "signed" } else { "not signed" }));
    }
    Outcome { findings: registration_findings(target, r), facts, ..Outcome::default() }
}

pub fn ports_outcome(target: &str, r: &PortsResult) -> Outcome {
    let addresses = r.addresses.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
    let mut facts = vec![Fact::new("Addresses probed", if addresses.is_empty() { "none" } else { &addresses })];
    for p in &r.ports {
        let state = match p.state {
            PortState::Open => "open",
            PortState::Closed => "closed (refused)",
            PortState::Filtered => "no answer",
            PortState::NoRoute => "no route from this network",
        };
        let banner = p.banner.as_deref().map(|b| format!(", banner: {b}")).unwrap_or_default();
        facts.push(Fact::new(format!("Port {} {}", p.port, p.service), format!("{state} on {}{banner}", p.address)));
    }
    Outcome { findings: ports_findings(target, r), facts, ..Outcome::default() }
}

fn extensions_text(e: &Extensions) -> String {
    let mut parts = vec![];
    for (on, name) in [(e.starttls, "STARTTLS"), (e.pipelining, "PIPELINING"), (e.eight_bit_mime, "8BITMIME")] {
        if on {
            parts.push(name.to_string());
        }
    }
    if let Some(n) = e.size {
        parts.push(format!("SIZE {n}"));
    }
    if !e.auth.is_empty() {
        parts.push(format!("AUTH {}", e.auth.join(" ")));
    }
    parts.extend(e.other.iter().cloned());
    if parts.is_empty() { "nothing".into() } else { parts.join(", ") }
}

pub fn smtp_outcome(r: &SmtpResult, expect_names: &[String]) -> Outcome {
    let peer = r.peer.map(|p| format!(" ({p})")).unwrap_or_default();
    let mut facts = vec![
        Fact::new("Server", format!("{}:{}{peer}", r.host, r.port)),
        Fact::new(
            "Reached",
            match r.reach {
                Reach::Answered => "answered",
                Reach::NoAnswer => "no answer",
                Reach::Refused => "refused",
                Reach::NoRoute => "no route from this network",
                Reach::Failed => "failed",
            },
        ),
    ];
    if let Some(b) = &r.banner {
        facts.push(Fact::new("Banner", format!("{} {}", b.code, b.text)));
    }
    if let Some(e) = &r.extensions {
        facts.push(Fact::new("Offers", extensions_text(e)));
    }
    facts.push(Fact::new(
        "STARTTLS",
        match &r.starttls {
            Starttls::NotApplicable => "not used, the port starts TLS at once".to_string(),
            Starttls::NotAttempted => "not tried".to_string(),
            Starttls::NotOffered => "not offered".to_string(),
            Starttls::Refused { code, text } => format!("refused: {code} {text}"),
            Starttls::HandshakeFailed(why) => format!("handshake failed: {why}"),
            Starttls::Upgraded => "upgraded to TLS".to_string(),
        },
    ));
    if let Some(t) = &r.tls {
        facts.push(Fact::new("Protocol", &t.version));
        facts.push(Fact::new("Cipher", &t.cipher));
        facts.push(Fact::new("Trust", format!("{:?}", t.trust)));
        if let Some(leaf) = t.chain.first() {
            facts.push(Fact::new("Certificate", format!("{}, expires {}", leaf.subject, leaf.not_after)));
        }
    }
    if let Some(f) = &r.failure {
        facts.push(Fact::new("Stopped", format!("{:?}: {}", f.stage, f.message)));
    }
    let details = r.extensions_after_tls.as_ref().map(|e| vec![Fact::new("Offers after STARTTLS", extensions_text(e))]).unwrap_or_default();
    Outcome { findings: smtp_findings(r, expect_names), facts, details_title: "After STARTTLS", details }
}

pub fn blacklist_outcome(target: &str, r: &BlacklistResult) -> Outcome {
    let mut facts = vec![];
    let mut details = vec![];
    for (subject, s) in &r.subjects {
        let kind = if s.kind == SubjectKind::Ip { "address" } else { "domain" };
        let listed: Vec<_> = s.lists.iter().filter(|(_, v)| v.state == State::Listed).collect();
        let unsure = s.lists.values().filter(|v| matches!(v.state, State::Refused | State::Unknown)).count();
        let mut line = if listed.is_empty() { format!("not listed on any of {} lists", s.lists.len() - unsure) } else { format!("listed on {} of {} lists", listed.len(), s.lists.len()) };
        if unsure > 0 {
            line += &format!(", {unsure} gave no verdict");
        }
        facts.push(Fact::new(format!("{subject} ({kind}, {})", s.source), line));
        for (name, v) in &listed {
            let why = if v.reason.is_empty() { v.codes.join(", ") } else { format!("{} ({})", v.reason, v.codes.join(", ")) };
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

    fn t(value: &str, kind: Kind) -> Target {
        Target { value: value.into(), kind }
    }

    #[test]
    fn propagation_asks_about_the_name_behind_the_target() {
        assert_eq!(check_name(&t("example.com", Kind::Domain)).as_deref(), Some("example.com"));
        assert_eq!(check_name(&t("www.example.com", Kind::Hostname)).as_deref(), Some("www.example.com"));
        assert_eq!(check_name(&t("a@example.com", Kind::Email)).as_deref(), Some("example.com"));
        assert_eq!(check_name(&t("192.0.2.1", Kind::Ip)), None);
    }

    #[test]
    fn a_domain_runs_every_check_and_a_host_name_the_short_list() {
        assert_eq!(automatic(Kind::Domain).len(), 7);
        assert_eq!(automatic(Kind::Email), automatic(Kind::Domain));
        assert_eq!(automatic(Kind::Hostname), [Section::Dns, Section::Web, Section::Tls, Section::Registration]);
        assert!(automatic(Kind::Ip).is_empty());
        assert!(automatic(Kind::Domain).iter().all(|s| wired(*s) && !s.is_on_demand()));
    }

    #[test]
    fn an_on_demand_check_is_never_watched() {
        assert!(Section::ALL.iter().filter(|s| s.is_on_demand()).all(|s| !watchable(*s)));
        assert!(watchable(Section::Dns) && watchable(Section::Web));
        assert!(!watchable(Section::Summary));
    }

    #[test]
    fn no_on_demand_check_is_ever_automatic() {
        for kind in [Kind::Domain, Kind::Hostname, Kind::Email, Kind::Ip] {
            assert!(automatic(kind).iter().all(|s| !s.is_on_demand()));
        }
    }

    #[test]
    fn a_registration_becomes_findings_plus_a_short_table() {
        let mut r = Registration::empty("example.com", zombo_core::registration::Source::Rdap, "https://rdap.example");
        r.registered = true;
        r.registrar = Some("Registrar Inc".into());
        r.nameservers = vec!["ns1.example.com".into()];
        let o = registration_outcome("example.com", &r);
        let lines = o.records();
        assert!(lines.contains(&"Registrar: Registrar Inc".to_string()));
        assert!(lines.contains(&"Nameserver: ns1.example.com".to_string()));
        assert!(o.details.is_empty());
    }

    #[test]
    fn a_delegation_lists_each_server_with_its_state() {
        use std::collections::{BTreeMap, BTreeSet};
        let r = DelegationResult {
            apex: "example.com".into(),
            parent: "com".into(),
            parent_ns: BTreeSet::from(["ns1.example.com".to_string()]),
            glue: BTreeMap::new(),
            servers: vec![zombo_core::delegation::DelegatedServer { name: "ns1.example.com".into(), address: None, state: ServerState::Unreachable, child_ns: None }],
            glue_served: BTreeMap::new(),
            unresolvable: vec![],
            cnames: vec![],
        };
        let lines = delegation_outcome(&r).records();
        assert!(lines.contains(&"Server ns1.example.com: unreachable".to_string()));
        assert!(lines.contains(&"Delegated nameserver: ns1.example.com".to_string()));
    }
    #[test]
    fn an_on_demand_check_can_be_asked_about_an_ip_but_an_automatic_one_cannot() {
        let ip = t("192.0.2.1", Kind::Ip);
        assert_eq!(name_for(Section::Ports, &ip).as_deref(), Some("192.0.2.1"));
        assert_eq!(name_for(Section::Blacklist, &ip).as_deref(), Some("192.0.2.1"));
        assert_eq!(name_for(Section::Dnssec, &ip), None);
        assert_eq!(name_for(Section::Smtp, &t("a@example.com", Kind::Email)).as_deref(), Some("example.com"));
    }

    #[test]
    fn nothing_on_demand_starts_with_a_target_whatever_its_kind() {
        for kind in [Kind::Domain, Kind::Hostname, Kind::Email, Kind::Ip] {
            for s in crate::ondemand::on_demand(kind) {
                assert!(s.is_on_demand() && wired(*s), "{s:?}");
                assert!(!automatic(kind).contains(s), "{s:?} would start by itself for {kind:?}");
            }
        }
    }

    #[test]
    fn a_silent_mail_port_reads_as_no_answer_and_not_as_down() {
        use zombo_core::ports::PortProbe;
        let r = PortsResult {
            addresses: vec!["192.0.2.1".parse().unwrap()],
            ports: vec![PortProbe { address: "192.0.2.1".parse().unwrap(), port: 25, service: "SMTP", state: PortState::Filtered, banner: None }],
        };
        let o = ports_outcome("mail.example.com", &r);
        assert!(o.records().contains(&"Port 25 SMTP: no answer on 192.0.2.1".to_string()));
        assert_eq!(o.findings.len(), 1);
        assert_eq!(o.findings[0].code, "hosting_reachability_mail_filtered");
        assert_eq!(o.findings[0].severity, zombo_core::Severity::Info);
    }

    #[test]
    fn a_banner_and_an_open_port_show_together() {
        use zombo_core::ports::PortProbe;
        let ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let r = PortsResult { addresses: vec![ip], ports: vec![PortProbe { address: ip, port: 22, service: "SSH", state: PortState::Open, banner: Some("SSH-2.0-x".into()) }] };
        assert!(ports_outcome("h", &r).records().contains(&"Port 22 SSH: open on 192.0.2.1, banner: SSH-2.0-x".to_string()));
    }

    #[test]
    fn an_smtp_server_that_never_answered_is_reported_as_no_answer_with_the_cores_finding() {
        let r = SmtpResult {
            host: "mail.example.com".into(),
            port: 25,
            mode: zombo_core::smtp::Mode::Starttls,
            reach: Reach::NoAnswer,
            peer: None,
            banner: None,
            extensions: None,
            starttls: Starttls::NotAttempted,
            tls: None,
            extensions_after_tls: None,
            failure: None,
        };
        let o = smtp_outcome(&r, &[]);
        let lines = o.records();
        assert!(lines.contains(&"Reached: no answer".to_string()));
        assert!(lines.contains(&"STARTTLS: not tried".to_string()));
        assert!(!o.findings.is_empty());
    }

    #[test]
    fn a_listed_address_is_called_out_and_every_list_is_kept_in_the_details() {
        use zombo_core::blacklist::{BlacklistResult, Subject, Verdict};
        let verdict = |state| Verdict { zone: "zen.example", delist: "", state, codes: vec!["127.0.0.2".into()], reason: String::new(), error: String::new() };
        let mut r = BlacklistResult::default();
        r.subjects.insert(
            "127.0.0.2".into(),
            Subject { kind: SubjectKind::Ip, source: "target".into(), lists: [("Spamhaus ZEN".to_string(), verdict(State::Listed)), ("SpamCop".to_string(), verdict(State::Clean))].into() },
        );
        let o = blacklist_outcome("127.0.0.2", &r);
        let lines = o.records();
        assert!(lines.contains(&"127.0.0.2 (address, target): listed on 1 of 2 lists".to_string()));
        assert!(lines.contains(&"Listed on Spamhaus ZEN: 127.0.0.2".to_string()));
        assert_eq!(o.details.len(), 2);
        assert!(!o.findings.is_empty());
    }

    #[test]
    fn a_domain_with_no_address_says_why_nothing_was_checked() {
        use zombo_core::blacklist::BlacklistResult;
        let r = BlacklistResult { resolve: Some("no mail host has an address".into()), ..BlacklistResult::default() };
        assert!(blacklist_outcome("example.com", &r).records().contains(&"Mail host addresses: no mail host has an address".to_string()));
    }

}
