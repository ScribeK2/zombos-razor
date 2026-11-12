use std::{net::SocketAddr, time::Duration};

use tokio::sync::mpsc::UnboundedSender;
use zombo_core::{
    check::{Check, Request},
    email_auth::{EmailAuthResult, email_auth, email_findings},
    ports::{PortState, PortsResult, QUICK, Timing as PortTiming, ports_findings, probe, resolve_target},
    propagation::{Scope, ask_vantage, default_resolvers, discover_nameservers, propagation_with},
    rdns::{RdnsResult, check_rdns},
    registration::{Endpoints, Registration, check_registration, registration_findings},
    resolver::{Resolver, system_resolvers},
    smtp::{Extensions, Reach, SmtpOptions, SmtpResult, Starttls, check_smtp, smtp_findings},
    target::{Kind, Target},
    web::{WebOptions, WebResult, check_web, parse_web_target, web_findings},
};

use crate::{
    diagnosis::PropEvent,
    outcome::{CheckEvent, Fact, Outcome},
    section::Section,
    settings_model::{Settings, budget},
    smtp_plan,
};

/// The Checks that run on their own when a target is submitted (DESIGN.md, "Checks per target kind").
pub fn automatic(kind: Kind) -> Vec<Section> {
    use Section::*;
    let listed: &[Section] = match kind {
        Kind::Domain | Kind::Email => &[Dns, Email, Web, Registration],
        Kind::Hostname => &[Dns, Web, Registration],
        Kind::Ip => &[],
    };
    Section::ALL
        .into_iter()
        .filter(|s| match s.check() {
            Some(check) => check.automatic_for.contains(&kind),
            None => listed.contains(s),
        })
        .collect()
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
    let takes_ip = section.is_on_demand() || section.check().is_some_and(|c| c.automatic_for.contains(&Kind::Ip));
    if takes_ip && target.kind == Kind::Ip { Some(target.value.clone()) } else { check_name(target) }
}

/// The ten public resolvers, then the rep's own that are not already among them.
fn propagation_resolvers(extra: &[SocketAddr]) -> Vec<zombo_core::propagation::Vantage> {
    let mut resolvers = default_resolvers();
    for &address in extra {
        if !resolvers.iter().any(|r| r.address == address) {
            resolvers.push(zombo_core::propagation::Vantage::resolver(
                &address.to_string(),
                "Added in settings",
                address,
            ));
        }
    }
    resolvers
}

pub async fn run_propagation(target: String, settings: Settings, tx: UnboundedSender<PropEvent>) {
    let _ = tx.send(PropEvent::Started);
    let limits = budget(Section::Dns, settings.timeout);
    let work = async {
        let resolvers = propagation_resolvers(&settings.resolvers);
        let bootstrap: Vec<SocketAddr> = resolvers.iter().map(|r| r.address).collect();
        let nameservers = discover_nameservers(&bootstrap, &target, 53, limits.query).await.unwrap_or_default();
        let ask_local = async {
            let answer = match crate::this_machine::vantage(&system_resolvers()) {
                Some(v) => ask_vantage(v, &target, Scope::All, limits.query).await,
                None => crate::this_machine::unavailable(),
            };
            let _ = tx.send(PropEvent::Local(Box::new(answer)));
        };
        let (result, ()) = tokio::join!(
            propagation_with(&resolvers, &nameservers, &target, Scope::All, limits.query, |a| {
                let _ = tx.send(PropEvent::Answer(Box::new(a.clone())));
            }),
            ask_local
        );
        result.map_err(|e| e.to_string())
    };
    let event = match tokio::time::timeout(limits.whole, work).await {
        Ok(result) => PropEvent::Finished(Box::new(result)),
        Err(_) => PropEvent::TimedOut,
    };
    let _ = tx.send(event);
}

/// What the tab asks of the Checks that take a choice: the SMTP port and host, the TLS port.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub smtp: smtp_plan::Request,
    pub tls_port: u16,
}

impl Default for Options {
    fn default() -> Self {
        Options { smtp: smtp_plan::Request::default(), tls_port: crate::tls_port::PRESETS[0] }
    }
}

pub async fn run_section(
    section: Section,
    name: String,
    settings: Settings,
    options: Options,
    tx: UnboundedSender<CheckEvent>,
) {
    let _ = tx.send(CheckEvent::Started);
    let event = match tokio::time::timeout(
        budget(section, settings.timeout).whole,
        produce(section, &name, &settings, options),
    )
    .await
    {
        Ok(result) => CheckEvent::Finished(Box::new(result)),
        Err(_) => CheckEvent::TimedOut,
    };
    let _ = tx.send(event);
}

/// A Check that does not take the chosen port keeps the system port, so the automatic TLS row is
/// the service on 443 whatever port the picker holds.
fn request_for<'a>(
    check: &Check,
    name: &'a str,
    query: Duration,
    bootstrap: &'a [SocketAddr],
    options: Options,
) -> Request<'a> {
    let request = Request::system(name, query, bootstrap);
    if check.takes_chosen_port { Request { tls_port: options.tls_port, ..request } } else { request }
}

async fn produce(section: Section, name: &str, settings: &Settings, options: Options) -> Result<Outcome, String> {
    let smtp = options.smtp;
    let query = budget(section, settings.timeout).query;
    let bootstrap: Vec<SocketAddr> = default_resolvers().iter().map(|r| r.address).collect();
    if let Some(check) = section.check() {
        return check.run(&request_for(check, name, query, &bootstrap, options)).await;
    }
    match section {
        Section::Email => {
            let resolver = bootstrap.first().copied().ok_or("no resolver is configured")?;
            let r = email_auth(resolver, name, &settings.selectors, query).await;
            if r.answered() {
                Ok(email_outcome(name, &r))
            } else {
                Err(format!("no answer from DNS resolver {resolver}"))
            }
        }
        Section::Web => {
            let (host, path) = parse_web_target(name).map_err(|e| e.to_string())?;
            let opts = WebOptions { timeout: query, ..WebOptions::default() };
            Ok(web_outcome(&host, &check_web(&host, &path, &opts).await))
        }
        Section::Registration => {
            check_registration(name, &Endpoints { proxy: settings.proxy.clone(), ..Endpoints::default() }, query)
                .await
                .map(|r| registration_outcome(name, &r))
                .map_err(|e| e.to_string())
        }
        Section::Ports => {
            let addresses = resolve_target(name, Duration::from_secs(4)).await.map_err(|e| e.to_string())?;
            Ok(ports_outcome(name, &probe(&addresses, QUICK, PortTiming::default()).await))
        }
        Section::Smtp => {
            let resolvers = system_resolvers();
            let asked = if resolvers.is_empty() { &bootstrap } else { &resolvers };
            let port = smtp.port;
            let plan = smtp_plan::run(name, smtp, &Resolver::new(asked, Duration::from_secs(5)), |host| async move {
                check_smtp(&host, port, &SmtpOptions::for_port(port)).await
            })
            .await;
            let r = &plan.result;
            let mut expect = vec![];
            if plan.host.parse::<std::net::IpAddr>().is_err() {
                expect.push(plan.host.clone());
            }
            if let (Some(ip), Reach::Answered, false) = (r.peer, r.reach, resolvers.is_empty())
                && let RdnsResult::Ip { ptrs, .. } =
                    check_rdns(&resolvers, &ip.to_string(), Duration::from_secs(3)).await
            {
                expect.extend(ptrs.into_iter().map(|p| p.name));
            }
            let mut outcome = smtp_outcome(r, &expect);
            let mut facts = smtp_plan::facts(&plan);
            facts.append(&mut outcome.facts);
            outcome.facts = facts;
            Ok(outcome)
        }
        other => Err(format!("{} has no Check behind it", other.label())),
    }
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
        .map(|(i, h)| {
            Fact::new(
                format!("Hop {}", i + 1),
                format!(
                    "{} {}{}",
                    h.status,
                    h.url,
                    h.location.as_ref().map(|l| format!(" to {l}")).unwrap_or_default()
                ),
            )
        })
        .collect();
    Outcome { findings: web_findings(host, r), facts, details_title: "Redirect chain", details }
}

pub fn registration_outcome(target: &str, r: &Registration) -> Outcome {
    let mut facts =
        vec![Fact::new("Domain", &r.domain), Fact::new("Registered", if r.registered { "yes" } else { "no" })];
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
    let details = r
        .extensions_after_tls
        .as_ref()
        .map(|e| vec![Fact::new("Offers after STARTTLS", extensions_text(e))])
        .unwrap_or_default();
    Outcome { findings: smtp_findings(r, expect_names), facts, details_title: "After STARTTLS", details }
}

#[cfg(test)]
mod tests {
    use zombo_core::{dnssec, tls};

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
        assert_eq!(automatic(Kind::Ip), [Section::Rdns]);
        assert!(automatic(Kind::Domain).iter().all(|s| wired(*s) && !s.is_on_demand()));
    }

    /// A label over 63 bytes is not a DNS name, so the Check fails before it sends a query.
    #[tokio::test]
    async fn a_section_with_a_descriptor_runs_the_descriptor() {
        let name = format!("{}.example.com", "a".repeat(64));
        let err = produce(Section::Dnssec, &name, &Settings::default(), Options::default()).await.unwrap_err();
        assert_eq!(err, format!("no nameservers found for {name}"));
        let err = produce(Section::Summary, &name, &Settings::default(), Options::default()).await.unwrap_err();
        assert_eq!(err, "Summary has no Check behind it");
    }

    #[test]
    fn only_the_on_demand_tls_row_takes_the_picked_port() {
        let options = Options { tls_port: 993, ..Options::default() };
        let port = |c| request_for(c, "example.com", Duration::from_secs(1), &[], options).tls_port;
        assert_eq!((port(&tls::CHECK), port(&tls::ON_PORT), port(&dnssec::CHECK)), (443, 993, 443));
    }

    #[test]
    fn an_ip_target_runs_reverse_dns_on_its_own_and_no_other_target_does() {
        assert_eq!(automatic(Kind::Ip), [Section::Rdns]);
        for kind in [Kind::Domain, Kind::Hostname, Kind::Email] {
            assert!(!automatic(kind).contains(&Section::Rdns), "{kind:?}");
        }
        let ip = t("192.0.2.1", Kind::Ip);
        assert_eq!(name_for(Section::Rdns, &ip).as_deref(), Some("192.0.2.1"));
        assert_eq!(name_for(Section::Dns, &ip), None, "the DNS Check still needs a name");
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
            ports: vec![PortProbe {
                address: "192.0.2.1".parse().unwrap(),
                port: 25,
                service: "SMTP",
                state: PortState::Filtered,
                banner: None,
            }],
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
        let r = PortsResult {
            addresses: vec![ip],
            ports: vec![PortProbe {
                address: ip,
                port: 22,
                service: "SSH",
                state: PortState::Open,
                banner: Some("SSH-2.0-x".into()),
            }],
        };
        assert!(
            ports_outcome("h", &r).records().contains(&"Port 22 SSH: open on 192.0.2.1, banner: SSH-2.0-x".to_string())
        );
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
    fn the_rep_s_resolvers_join_the_ten_public_ones_without_repeating_any() {
        let own: SocketAddr = "192.0.2.53:53".parse().unwrap();
        let already: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let all = propagation_resolvers(&[own, already, own]);
        assert_eq!(all.len(), default_resolvers().len() + 1);
        assert_eq!(all.last().map(|v| v.address), Some(own));
        assert_eq!(all.iter().filter(|v| v.address == already).count(), 1);
        assert_eq!(propagation_resolvers(&[]).len(), default_resolvers().len());
    }
}
