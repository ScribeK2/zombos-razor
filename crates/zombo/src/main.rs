//! `zombo`: the command-line front end to zombo-core.

use std::{
    net::SocketAddr,
    process::ExitCode,
    time::{Duration, SystemTime},
};

use zombo_core::email_auth::{Alignment, EffectiveAll, KeyType, email_auth, email_findings, parse_selectors};
use zombo_core::evidence::{headers, maillog};
use zombo_core::web::{CertCheck, WebOptions, check_web, parse_web_target, web_findings};
use zombo_core::{
    Finding, Severity,
    delegation::{Ports, ServerState, check_delegation, delegation_findings},
    dnssec::{check_dnssec, dnssec_findings, validating_resolvers},
    propagation::{
        Scope, Vantage, VantageAnswer, VantageKind, default_resolvers, discover_nameservers, propagation_findings,
        propagation_with,
    },
    registration::{Endpoints, Source, check_registration, registration_findings},
    target::{Kind, parse_target},
};
use zombo_core::{
    blacklist::{Options as BlacklistOptions, State, SubjectKind, blacklist_findings, check_blacklist},
    rdns::{RdnsResult, check_rdns, rdns_findings},
    resolver::system_resolvers,
};
use zombo_core::{
    ports::{
        FULL, PortState, QUICK, ServicePort, Timing, has_ipv6, ports_findings, probe, resolve_target, service_for,
    },
    tls::{Trust, check_tls, tls_findings},
};
use zombo_core::{
    smtp::{Mode, Reach, SmtpOptions, Starttls, check_smtp, smtp_findings, valid_ehlo_name},
    tls_extras::{caa_findings, check_caa, ocsp_findings},
};

const USAGE: &str = "usage: zombo delegation <domain|host> [--resolver ip[:port]]... [--timeout-ms N] [--json]\n       zombo registration <domain|host> [--timeout-ms N] [--json]\n       zombo dnssec <domain|host> [--resolver ip[:port]]... [--timeout-ms N] [--json]\n       zombo email <domain|host> [--selector NAME]... [--resolver ip[:port]] [--timeout-ms N] [--json]\n       zombo web <url|host> [--origin IP [--insecure-origin]] [--resolver ip[:port]] [--timeout-ms N] [--json]\n       zombo blacklist <ip|domain|host> [--resolver ip[:port]]... [--timeout-ms N] [--json]\n       zombo rdns <ip|host> [--resolver ip[:port]]... [--timeout-ms N] [--json]\n       zombo evidence headers|maillog [FILE|-] [--json]\n       zombo tls <host[:port]> [--timeout-ms N] [--json]\n       zombo smtp <host[:port]> [--implicit-tls | --starttls] [--ehlo NAME] [--resolver ip[:port]]... [--timeout-ms N] [--json]\n       zombo caa <domain|host> [--port N] [--no-cert] [--resolver ip[:port]]... [--timeout-ms N] [--json]\n       zombo ports <host|ip> [--port N]... [--full] [--timeout-ms N] [--json]\n       zombo propagation <domain|host> [--scope all|mail|web] [--resolver ip[:port]]... [--nameserver ip[:port]]... [--no-authoritative] [--timeout-ms N] [--json]\n       zombo run <id> <target> [--timeout-ms N] [--resolver ip[:port]]... [--port N] [--selector NAME]... [--json]\n       zombo checks [--json]";

fn addr(v: &str) -> Result<SocketAddr, String> {
    zombo_core::resolver::parse_addr(v)
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("zombo: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Vec<String>) -> Result<(), String> {
    let mut it = args.into_iter();
    match it.next().as_deref() {
        Some("--version") => {
            println!("zombo {}", zombo_core::VERSION);
            Ok(())
        }
        Some("propagation") => propagation(it).await,
        Some("delegation") => delegation(it).await,
        Some("registration") => registration(it).await,
        Some("dnssec") => dnssec(it).await,
        Some("email") => email(it).await,
        Some("web") => web(it).await,
        Some("blacklist") => blacklist(it).await,
        Some("rdns") => rdns(it).await,
        Some("evidence") => evidence(it),
        Some("tls") => tls(it).await,
        Some("ports") => ports(it).await,
        Some("smtp") => smtp(it).await,
        Some("caa") => caa(it).await,
        Some("run") => run_check(it).await,
        Some("checks") => checks(it),
        _ => Err(USAGE.into()),
    }
}

const EMAIL_USAGE: &str =
    "usage: zombo email <domain|host> [--selector NAME]... [--resolver ip[:port]] [--timeout-ms N] [--json]";

async fn email(mut it: std::vec::IntoIter<String>) -> Result<(), String> {
    let (mut target, mut json, mut timeout, mut resolver) = (None, false, Duration::from_secs(4), None);
    let mut selectors = vec![];
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--timeout-ms" => {
                timeout =
                    Duration::from_millis(value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?)
            }
            "--resolver" => resolver = Some(addr(&value("--resolver")?)?),
            "--selector" => selectors.push(value("--selector")?),
            f if f.starts_with("--") => return Err(format!("unknown option {f}\n{EMAIL_USAGE}")),
            _ if target.is_none() => target = Some(a),
            _ => return Err(EMAIL_USAGE.into()),
        }
    }
    let t = parse_target(&target.ok_or(EMAIL_USAGE)?)?;
    if !matches!(t.kind, Kind::Domain | Kind::Hostname) {
        return Err(format!("email needs a domain or host name, not {:?}", t.kind));
    }
    let selectors = parse_selectors(&selectors)?;
    let Some(resolver) = resolver.or_else(|| default_resolvers().first().map(|v| v.address)) else {
        return Err("no default DNS resolver is configured".into());
    };
    let r = email_auth(resolver, &t.value, &selectors, timeout).await;
    if !r.answered() {
        return Err(format!("no answer from DNS resolver {resolver}"));
    }
    let findings = email_findings(&t.value, &r);
    if json {
        let out = serde_json::json!({ "result": r, "findings": findings });
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        return Ok(());
    }
    let list = |v: &[String]| if v.is_empty() { "-".to_string() } else { v.join(", ") };
    let records = |v: &[String], err: &Option<String>| match (v, err) {
        (_, Some(e)) => format!("lookup failed: {e}"),
        ([], _) => "none".to_string(),
        ([one], _) => one.clone(),
        (many, _) => format!("{} records (receivers ignore them)", many.len()),
    };
    println!("{} ({:?}) via {resolver}", t.value, t.kind);
    let s = &r.spf;
    println!("  {:<8} {}", "SPF", records(&s.records, &s.lookup_error));
    if s.tree.is_some() {
        let all = match s.all {
            EffectiveAll::All(q) => format!("{}all", q.symbol()),
            EffectiveAll::Absent => "no all".to_string(),
            EffectiveAll::Unknown => "unknown (behind an unresolved redirect)".to_string(),
        };
        let more = if s.truncated { "more than " } else { "" };
        println!("  {:<8} {more}{}/10 DNS lookups, {} void; {all}", "", s.lookups, s.void_lookups);
    }
    // A wildcard `*._domainkey` null record revokes every selector at once, so revoked keys are counted, not listed.
    let revoked = r.dkim.keys.iter().filter(|k| k.revoked).count();
    let mut keys: Vec<String> = r
        .dkim
        .keys
        .iter()
        .filter(|k| !k.revoked)
        .map(|k| match (&k.error, k.bits) {
            (Some(e), _) => format!("{} ({e})", k.selector),
            (_, Some(bits)) => format!("{} ({} {bits}-bit)", k.selector, k.key_type),
            _ if k.key_type == KeyType::Rsa => k.selector.clone(),
            _ => format!("{} ({})", k.selector, k.key_type),
        })
        .collect();
    if revoked > 0 {
        keys.push(format!("{revoked} revoked"));
    }
    let dkim =
        if keys.is_empty() { format!("none found among {} selectors", r.dkim.checked.len()) } else { keys.join(", ") };
    println!("  {:<8} {dkim}", "DKIM");
    let d = &r.dmarc;
    let dmarc = match &d.parsed {
        Some(p) => {
            let sp = p.subdomain_policy.map_or(String::new(), |sp| format!("; sp={sp}"));
            let policy = p.policy.map_or("no valid policy".to_string(), |p| format!("p={p}"));
            let strict = |a: Alignment| if a == Alignment::Strict { "s" } else { "r" };
            format!(
                "{policy}{sp}; pct={}; adkim={}; aspf={}; rua={}",
                p.pct,
                strict(p.adkim),
                strict(p.aspf),
                list(&p.rua)
            )
        }
        None => records(&d.records, &d.lookup_error),
    };
    println!("  {:<8} {dmarc}", "DMARC");
    println!("  {:<8} {}", "TLS-RPT", records(&r.tls_rpt.records, &r.tls_rpt.lookup_error));
    println!("  {:<8} {}", "BIMI", records(&r.bimi.records, &r.bimi.lookup_error));
    println!("  {:<8} {}", "MTA-STS", records(&r.mta_sts.records, &r.mta_sts.lookup_error));
    if !r.mta_sts.records.is_empty() {
        println!("  {:<8} (the policy file is not fetched)", "");
    }
    println!();
    print_findings(&findings);
    Ok(())
}

fn print_findings(findings: &[Finding]) {
    for f in findings {
        let tag = match f.severity {
            Severity::Ok => "ok",
            Severity::Info => "info",
            Severity::Warning => "WARNING",
            Severity::Critical => "CRITICAL",
        };
        println!("[{tag}] {}: {}", f.title, f.message);
        if let Some(r) = &f.recommendation {
            println!("        {r}");
        }
    }
}

async fn delegation(mut it: std::vec::IntoIter<String>) -> Result<(), String> {
    let (mut target, mut json, mut timeout) = (None, false, Duration::from_secs(4));
    let mut bootstrap: Vec<SocketAddr> = vec![];
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--timeout-ms" => {
                timeout =
                    Duration::from_millis(value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?)
            }
            "--resolver" => bootstrap.push(addr(&value("--resolver")?)?),
            f if f.starts_with("--") => return Err(format!("unknown option {f}\n{USAGE}")),
            _ if target.is_none() => target = Some(a),
            _ => return Err(USAGE.into()),
        }
    }
    let t = parse_target(&target.ok_or(USAGE)?)?;
    if !matches!(t.kind, Kind::Domain | Kind::Hostname) {
        return Err(format!("delegation needs a domain or host name, not {:?}", t.kind));
    }
    if bootstrap.is_empty() {
        bootstrap = default_resolvers().iter().map(|r| r.address).collect();
    }
    let r = check_delegation(&bootstrap, &t.value, Ports::default(), timeout).await.map_err(|e| e.to_string())?;
    let findings = delegation_findings(&r);
    if json {
        let out = serde_json::json!({ "result": r, "findings": findings });
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        return Ok(());
    }
    println!("{} is delegated from {}", r.apex, r.parent);
    for s in &r.servers {
        let glue = r.glue.get(&s.name).map(|g| match g.len() {
            1..=2 => g.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
            n => format!("{n} addresses"),
        });
        let state = match &s.state {
            ServerState::Ok { serial } => format!("authoritative, serial {serial}"),
            ServerState::Unreachable => "no answer".to_string(),
            ServerState::Lame { why, .. } => format!("LAME: {why}"),
        };
        println!("  {:<32} glue: {:<24} {state}", s.name, glue.unwrap_or_else(|| "-".into()));
    }
    println!();
    print_findings(&findings);
    Ok(())
}

async fn dnssec(mut it: std::vec::IntoIter<String>) -> Result<(), String> {
    const USAGE: &str = "usage: zombo dnssec <domain|host> [--resolver ip[:port]]... [--timeout-ms N] [--json]";
    let (mut target, mut json, mut timeout) = (None, false, Duration::from_secs(4));
    let mut resolvers = vec![];
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--timeout-ms" => {
                timeout =
                    Duration::from_millis(value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?)
            }
            "--resolver" => {
                let v = value("--resolver")?;
                resolvers.push(Vantage::resolver(&v, "custom", addr(&v)?));
            }
            f if f.starts_with("--") => return Err(format!("unknown option {f}\n{USAGE}")),
            _ if target.is_none() => target = Some(a),
            _ => return Err(USAGE.into()),
        }
    }
    let t = parse_target(&target.ok_or(USAGE)?)?;
    if !matches!(t.kind, Kind::Domain | Kind::Hostname) {
        return Err(format!("dnssec needs a domain or host name, not {:?}", t.kind));
    }
    // Custom resolvers are both asked for the verdict and used to find the zone; the
    // defaults find the zone through the wide public list and judge by the validating four.
    let bootstrap: Vec<SocketAddr> =
        if resolvers.is_empty() { default_resolvers() } else { resolvers.clone() }.iter().map(|r| r.address).collect();
    if resolvers.is_empty() {
        resolvers = validating_resolvers();
    }
    let r = check_dnssec(&bootstrap, &resolvers, &t.value, 53, SystemTime::now(), timeout)
        .await
        .map_err(|e| e.to_string())?;
    let findings = dnssec_findings(&r);
    if json {
        let out = serde_json::json!({ "result": r, "findings": findings });
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        return Ok(());
    }
    println!("DNSSEC for {}", r.apex);
    println!("\nValidating resolvers:");
    for v in &r.resolvers {
        println!("  {:<14} {}", v.resolver, v.status.label());
    }
    println!("\nDS records at the parent:");
    for d in &r.ds {
        println!(
            "  key tag {:<6} {:<24} {:<8} matches a served key: {}",
            d.ds.key_tag.to_string(),
            d.ds.algorithm.to_string(),
            d.ds.digest_type.to_string(),
            if d.matched { "yes" } else { "NO" }
        );
    }
    if r.ds.is_empty() {
        println!("  none");
    }
    println!("\nNameservers:");
    for n in &r.nameservers {
        if let Some(e) = &n.error {
            println!("  {:<32} no answer ({e})", n.name);
            continue;
        }
        let keys: Vec<String> = n
            .dnskeys
            .iter()
            .map(|k| format!("{} {} {}", k.key_tag, if k.is_ksk() { "KSK" } else { "ZSK" }, k.algorithm))
            .collect();
        println!("  {:<32} DNSKEY: {}", n.name, if keys.is_empty() { "none".to_string() } else { keys.join(", ") });
        if let Some(s) = &n.soa_rrsig {
            let when = SystemTime::UNIX_EPOCH + Duration::from_secs(r.checked_at);
            println!("  {:<32} SOA signature by key {}: {}", "", s.key_tag, s.window(when).describe());
        }
    }
    println!();
    print_findings(&findings);
    Ok(())
}

async fn propagation(mut it: std::vec::IntoIter<String>) -> Result<(), String> {
    let (mut target, mut scope, mut json, mut timeout) = (None, Scope::All, false, Duration::from_secs(4));
    let (mut resolvers, mut nameservers, mut no_auth) = (vec![], vec![], false);
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--scope" => scope = value("--scope")?.parse()?,
            "--timeout-ms" => {
                timeout =
                    Duration::from_millis(value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?)
            }
            "--no-authoritative" => no_auth = true,
            "--resolver" => {
                let v = value("--resolver")?;
                resolvers.push(Vantage::resolver(&v, "custom", addr(&v)?));
            }
            "--nameserver" => {
                let v = value("--nameserver")?;
                nameservers.push(Vantage::nameserver(&v, addr(&v)?));
            }
            f if f.starts_with("--") => return Err(format!("unknown option {f}\n{USAGE}")),
            _ if target.is_none() => target = Some(a),
            _ => return Err(USAGE.into()),
        }
    }
    let t = parse_target(&target.ok_or(USAGE)?)?;
    if !matches!(t.kind, Kind::Domain | Kind::Hostname) {
        return Err(format!("propagation needs a domain or host name, not {:?}", t.kind));
    }
    if resolvers.is_empty() {
        resolvers = default_resolvers();
    }

    if !no_auth && nameservers.is_empty() {
        let bootstrap: Vec<SocketAddr> = resolvers.iter().map(|r| r.address).collect();
        match discover_nameservers(&bootstrap, &t.value, 53, timeout).await {
            Ok(found) => nameservers = found,
            Err(e) => eprintln!("zombo: skipping the authoritative nameservers: {e}"),
        }
    }

    let show = |a: &VantageAnswer| {
        if json {
            return;
        }
        let r = &a.vantage;
        match (&a.error, a.rcode) {
            (Some(e), _) => println!("  {:<14} {:<16} {e}", r.name, r.location),
            (None, rcode) => println!(
                "  {:<14} {:<16} {:?}  {} record types answered{}",
                r.name,
                r.location,
                rcode.map_or_else(|| "no code".to_string(), |c| format!("{c:?}")),
                a.answers.len(),
                if a.authoritative == Some(false) && r.kind == VantageKind::Authoritative {
                    "  (NOT authoritative)"
                } else {
                    ""
                }
            ),
        }
    };
    if !json {
        println!(
            "{} ({:?}): {} resolvers, {} authoritative nameservers",
            t.value,
            t.kind,
            resolvers.len(),
            nameservers.len()
        );
    }
    let res =
        propagation_with(&resolvers, &nameservers, &t.value, scope, timeout, show).await.map_err(|e| e.to_string())?;
    let findings = propagation_findings(&t.value, &res);
    if json {
        let out = serde_json::json!({ "result": res, "findings": findings });
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        return Ok(());
    }
    println!();
    for ty in &res.types {
        let mut variants: Vec<(Vec<String>, Vec<&str>)> = vec![];
        for a in res.nameservers.iter().chain(&res.resolvers).filter(|a| a.error.is_none() && !a.failed.contains(ty)) {
            let vals = a.answers.get(ty).cloned().unwrap_or_default();
            match variants.iter_mut().find(|(v, _)| *v == vals) {
                Some((_, who)) => who.push(&a.vantage.name),
                None => variants.push((vals, vec![&a.vantage.name])),
            }
        }
        let mark = if res.disagree.contains(ty) { "DIFFERS" } else { "agree" };
        println!("{ty:<6} {mark}");
        for (vals, who) in variants {
            let v = if vals.is_empty() { "(none)".to_string() } else { vals.join(" | ") };
            println!("       {v}  <- {}", who.join(", "));
        }
    }
    println!();
    println!("Agreement: {} - {}", res.agreement.label(), res.agreement.reason());
    println!();
    print_findings(&findings);
    Ok(())
}

async fn registration(mut it: std::vec::IntoIter<String>) -> Result<(), String> {
    let (mut target, mut json, mut timeout) = (None, false, Duration::from_secs(10));
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--timeout-ms" => {
                timeout =
                    Duration::from_millis(value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?)
            }
            f if f.starts_with("--") => return Err(format!("unknown option {f}\n{USAGE}")),
            _ if target.is_none() => target = Some(a),
            _ => return Err(USAGE.into()),
        }
    }
    let t = parse_target(&target.ok_or(USAGE)?)?;
    if !matches!(t.kind, Kind::Domain | Kind::Hostname) {
        return Err(format!("registration needs a domain or host name, not {:?}", t.kind));
    }
    let r = check_registration(&t.value, &Endpoints::default(), timeout).await.map_err(|e| e.to_string())?;
    let findings = registration_findings(&t.value, &r);
    if json {
        let out = serde_json::json!({ "result": r, "findings": findings });
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        return Ok(());
    }
    let via = match r.source {
        Source::Rdap => "RDAP",
        Source::Whois => "WHOIS",
    };
    println!("{}: {} (via {via}, {})", r.domain, if r.registered { "registered" } else { "not registered" }, r.server);
    if let Some(why) = &r.rdap_error {
        println!("  RDAP was not used: {why}");
    }
    let row = |label: &str, v: Option<String>| {
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            println!("  {label:<12} {v}");
        }
    };
    row("Registrar", r.registrar.clone());
    row("Created", r.created.as_ref().map(ToString::to_string));
    row("Updated", r.updated.as_ref().map(ToString::to_string));
    row("Expires", r.expires.as_ref().map(ToString::to_string));
    row("Status", Some(r.statuses.join(", ")));
    row("Nameservers", Some(r.nameservers.join(", ")));
    row("DNSSEC", r.dnssec.map(|s| if s { "signed" } else { "unsigned" }.to_string()));
    println!();
    print_findings(&findings);
    Ok(())
}

const WEB_USAGE: &str =
    "usage: zombo web <url|host> [--origin IP [--insecure-origin]] [--resolver ip[:port]] [--timeout-ms N] [--json]";

async fn web(mut it: std::vec::IntoIter<String>) -> Result<(), String> {
    let (mut target, mut json, mut opts) = (None, false, WebOptions::default());
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--timeout-ms" => {
                opts.timeout =
                    Duration::from_millis(value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?)
            }
            "--origin" => {
                let v = value("--origin")?;
                opts.origin =
                    Some(v.trim_matches(['[', ']']).parse().map_err(|_| format!("{v:?} is not an IP address"))?);
            }
            "--insecure-origin" => opts.origin_cert = CertCheck::SkipVerification,
            "--resolver" => opts.resolver = Some(addr(&value("--resolver")?)?),
            f if f.starts_with("--") => return Err(format!("unknown option {f}\n{WEB_USAGE}")),
            _ if target.is_none() => target = Some(a),
            _ => return Err(WEB_USAGE.into()),
        }
    }
    if opts.origin_cert == CertCheck::SkipVerification && opts.origin.is_none() {
        return Err(format!("--insecure-origin only applies with --origin\n{WEB_USAGE}"));
    }
    let (host, path) = parse_web_target(&target.ok_or(WEB_USAGE)?).map_err(|e| e.to_string())?;
    let r = check_web(&host, &path, &opts).await;
    let findings = web_findings(&host, &r);
    if json {
        let out = serde_json::json!({ "result": r, "findings": findings });
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        return Ok(());
    }
    println!("{}", r.url);
    if let Some(e) = &r.https_error {
        println!("  HTTPS failed: {e}");
    }
    for h in &r.chain {
        let to = h.location.as_deref().map_or(String::new(), |l| format!("  -> {l}"));
        println!("  {} {}{to}", h.status, h.url);
    }
    if let Some(e) = &r.error {
        println!("  failed: {e}");
    }
    if let Some(s) = r.status {
        println!(
            "  HTTP {s} in {} ms{}",
            r.time_ms,
            r.server.as_deref().map_or(String::new(), |s| format!(", server {s}"))
        );
    }
    if r.hosting.dns_error.is_none() {
        let cname = if r.hosting.cname_chain.is_empty() {
            String::new()
        } else {
            format!(" via {}", r.hosting.cname_chain.join(" > "))
        };
        let ips: Vec<String> = r.hosting.addresses.iter().map(ToString::to_string).collect();
        println!(
            "  {}{cname}: {}",
            r.hosting.host,
            if ips.is_empty() { "no addresses".to_string() } else { ips.join(", ") }
        );
    }
    if let Some(o) = &r.origin {
        let a = &o.answer;
        println!(
            "  origin {}: {}",
            o.ip,
            a.status.map_or_else(
                || format!("no answer ({})", a.error.as_deref().unwrap_or("unknown")),
                |s| format!("HTTP {s} in {} ms", a.time_ms)
            )
        );
    }
    println!();
    print_findings(&findings);
    Ok(())
}

const BLACKLIST_USAGE: &str =
    "usage: zombo blacklist <ip|domain|host> [--resolver ip[:port]]... [--timeout-ms N] [--json]";
const RDNS_USAGE: &str = "usage: zombo rdns <ip|host> [--resolver ip[:port]]... [--timeout-ms N] [--json]";

/// What `blacklist` and `rdns` share: a target, the resolvers to ask (the machine's own unless
/// `--resolver` is given), a per-question timeout and the output form.
fn dns_args(
    mut it: std::vec::IntoIter<String>,
    usage: &str,
    what: &str,
) -> Result<(zombo_core::target::Target, Vec<SocketAddr>, Duration, bool), String> {
    let (mut target, mut json, mut timeout, mut resolvers) = (None, false, Duration::from_secs(3), vec![]);
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--timeout-ms" => {
                timeout =
                    Duration::from_millis(value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?)
            }
            "--resolver" => resolvers.push(addr(&value("--resolver")?)?),
            f if f.starts_with("--") => return Err(format!("unknown option {f}\n{usage}")),
            _ if target.is_none() => target = Some(a),
            _ => return Err(usage.into()),
        }
    }
    let t = parse_target(&target.ok_or(usage)?)?;
    if t.kind == Kind::Email {
        return Err(format!("{what} needs an IP address or a domain or host name, not an email address"));
    }
    if resolvers.is_empty() {
        resolvers = system_resolvers();
    }
    if resolvers.is_empty() {
        return Err("no DNS resolver found in /etc/resolv.conf; pass --resolver ip[:port]".into());
    }
    Ok((t, resolvers, timeout, json))
}

fn join<T: ToString>(items: &[T]) -> String {
    items.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

async fn blacklist(it: std::vec::IntoIter<String>) -> Result<(), String> {
    let (t, resolvers, timeout, json) = dns_args(it, BLACKLIST_USAGE, "blacklist")?;
    let r = check_blacklist(
        &resolvers,
        &t.value,
        BlacklistOptions { query_timeout: timeout, overall: (timeout * 5).max(BlacklistOptions::default().overall) },
    )
    .await;
    let findings = blacklist_findings(&t.value, &r);
    if json {
        let out = serde_json::json!({ "result": r, "findings": findings });
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        return Ok(());
    }
    println!("{} ({:?}) via {}", t.value, t.kind, join(&resolvers));
    for (subject, s) in &r.subjects {
        let kind = if s.kind == SubjectKind::Ip { "address" } else { "domain" };
        println!("  {subject} ({kind}, {})", s.source);
        for (name, v) in &s.lists {
            let state = match v.state {
                State::Listed => format!("LISTED {}", v.codes.join(", ")),
                State::Clean => "not listed".to_string(),
                State::Refused => "refused the query".to_string(),
                State::Unknown => format!("no verdict ({})", v.error),
            };
            println!("    {name:<20} {state}");
        }
    }
    println!();
    print_findings(&findings);
    Ok(())
}

async fn rdns(it: std::vec::IntoIter<String>) -> Result<(), String> {
    let (t, resolvers, timeout, json) = dns_args(it, RDNS_USAGE, "rdns")?;
    let r = check_rdns(&resolvers, &t.value, timeout).await;
    let findings = rdns_findings(&r);
    if json {
        let out = serde_json::json!({ "result": r, "findings": findings });
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        return Ok(());
    }
    println!("{} ({:?}) via {}", t.value, t.kind, join(&resolvers));
    match &r {
        RdnsResult::Ip { ptrs, ptr_error, .. } => {
            if let Some(e) = ptr_error {
                println!("  PTR lookup failed: {e}");
            }
            for p in ptrs {
                let back = match (&p.forward_error, p.confirmed) {
                    (Some(e), _) => format!("not confirmed ({e})"),
                    (None, true) => "resolves back".to_string(),
                    (None, false) if p.addresses.is_empty() => "does NOT resolve back (it has no address)".to_string(),
                    (None, false) => format!("does NOT resolve back (it resolves to {})", join(&p.addresses)),
                };
                println!("  PTR {}  {back}", p.name);
            }
        }
        RdnsResult::Host { addresses, errors, .. } => {
            for a in addresses {
                println!("  {a}");
            }
            for e in errors {
                println!("  lookup failed: {e}");
            }
        }
    }
    println!();
    print_findings(&findings);
    Ok(())
}

const EVIDENCE_USAGE: &str =
    "usage: zombo evidence headers|maillog [FILE|-] [--json]   (reads stdin when FILE is - or absent)";

fn evidence(mut it: std::vec::IntoIter<String>) -> Result<(), String> {
    let kind = it.next().ok_or(EVIDENCE_USAGE)?;
    let (mut file, mut json) = (None, false);
    for a in it {
        match a.as_str() {
            "--json" => json = true,
            f if f.starts_with("--") => return Err(format!("unknown option {f}\n{EVIDENCE_USAGE}")),
            _ if file.is_none() => file = Some(a),
            _ => return Err(EVIDENCE_USAGE.into()),
        }
    }
    if !matches!(kind.as_str(), "headers" | "maillog") {
        return Err(EVIDENCE_USAGE.into());
    }
    let text = match file.as_deref() {
        None | Some("-") => zombo_core::evidence::read_limited(std::io::stdin().lock()),
        Some(path) => {
            zombo_core::evidence::read_limited(std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?)
        }
    }
    .map_err(|e| e.to_string())?;
    if kind == "headers" {
        let a = headers::analyse_headers(&text).map_err(|e| e.to_string())?;
        let findings = headers::header_findings(&a);
        if json {
            return print_json(&serde_json::json!({ "result": a, "findings": findings }));
        }
        print_headers(&a);
        print_findings(&findings);
    } else {
        let a = maillog::analyse_maillog(&text).map_err(|e| e.to_string())?;
        let findings = maillog::maillog_findings(&a);
        if json {
            return print_json(&serde_json::json!({ "result": a, "findings": findings }));
        }
        print_maillog(&a);
        print_findings(&findings);
    }
    Ok(())
}

fn print_json(v: &serde_json::Value) -> Result<(), String> {
    println!("{}", serde_json::to_string_pretty(v).map_err(|e| e.to_string())?);
    Ok(())
}

/// A table cell: long hostile names are cut so a row stays one line.
fn cell(s: &str, width: usize) -> String {
    match s.char_indices().nth(width) {
        Some((i, _)) => format!("{}...", &s[..i]),
        None => s.to_string(),
    }
}

fn delay_text(seconds: Option<i64>) -> String {
    match seconds {
        None => "-".into(),
        Some(s) if s < 0 => format!("{s}s (clock skew)"),
        Some(s) if s < 60 => format!("{s}s"),
        Some(s) if s < 3600 => format!("{}m {}s", s / 60, s % 60),
        Some(s) => format!("{:.1}h", s as f64 / 3600.0),
    }
}

fn print_headers(a: &headers::HeaderAnalysis) {
    println!("From: {}   Subject: {}", cell(&a.headers.from, 80), cell(&a.headers.subject, 80));
    println!("{:<4} {:<44} {:<32} delay", "hop", "from", "by");
    for (i, h) in a.hops.iter().enumerate() {
        let who = match h.from_ip {
            Some(ip) => format!("{} [{ip}]", cell(&h.from_host, 30)),
            None => cell(&h.from_host, 44),
        };
        println!("{:<4} {:<44} {:<32} {}", i + 1, who, cell(&h.by_host, 32), delay_text(h.delay_s));
    }
    if a.hops.is_empty() {
        println!("(no Received headers)");
    }
    if let Some(total) = a.total_transit_s {
        println!("total transit {}", delay_text(Some(total)));
    }
    println!();
    let verdict = |v: &Option<headers::Verdict>| v.as_ref().map_or("-".to_string(), ToString::to_string);
    println!("  {:<12} {}", "SPF", verdict(&a.auth.spf));
    let dkim = match a.auth.dkim_domain.as_str() {
        "" => verdict(&a.auth.dkim),
        d => format!("{} ({})", verdict(&a.auth.dkim), cell(d, 60)),
    };
    println!("  {:<12} {dkim}", "DKIM");
    println!("  {:<12} {}", "DMARC", verdict(&a.auth.dmarc));
    if let Some(ip) = a.delivering_ip {
        println!("  {:<12} {ip}", "Delivered by");
    }
    if let Some(ip) = a.origin_ip.filter(|ip| Some(*ip) != a.delivering_ip) {
        println!("  {:<12} {ip} (from the sender's own Received line; can be forged)", "Origin");
    }
    println!();
}

fn print_maillog(a: &maillog::MailLogAnalysis) {
    const SHOWN: usize = 200;
    for m in a.messages.iter().take(SHOWN) {
        let to: Vec<String> = m.recipients.iter().map(|r| cell(&r.to, 60)).collect();
        let to = if to.is_empty() { "(no delivery line)".to_string() } else { to.join(", ") };
        let verdict = format!("{:?}", m.verdict).to_lowercase();
        let from = if m.from.is_empty() { "?" } else { &m.from };
        println!("{:<20} {verdict:<10} {} -> {to}", cell(&m.queue_id, 20), cell(from, 60));
        for r in m.recipients.iter().filter(|r| r.status != Some(maillog::Status::Sent)) {
            if let Some(reason) = r.reason {
                println!("{:<31} {}: {}", "", cell(&r.to, 60), reason.text());
            }
        }
    }
    if a.messages.len() > SHOWN {
        println!("... and {} more messages (use --json for all)", a.messages.len() - SHOWN);
    }
    if !a.rejections.is_empty() {
        println!("{} mail(s) refused at our server before queueing", a.rejections.len());
    }
    println!("{} message(s), {} line(s) that are not Postfix or Dovecot", a.messages.len(), a.unparsed);
    println!();
}

const TLS_USAGE: &str = "usage: zombo tls <host[:port]> [--timeout-ms N] [--json]";

const PORTS_USAGE: &str = "usage: zombo ports <host|ip> [--port N]... [--full] [--timeout-ms N] [--json]";

fn split_port(raw: &str) -> (&str, Option<u16>) {
    match raw.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') || h.ends_with(']') => match p.parse() {
            Ok(port) => (h, Some(port)),
            Err(_) => (raw, None),
        },
        _ => (raw, None),
    }
}

async fn tls(mut it: std::vec::IntoIter<String>) -> Result<(), String> {
    let (mut target, mut json, mut timeout) = (None, false, Duration::from_secs(10));
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => json = true,
            "--timeout-ms" => {
                timeout = Duration::from_millis(
                    it.next()
                        .ok_or("--timeout-ms needs a value")?
                        .parse()
                        .map_err(|_| "--timeout-ms needs a number")?,
                )
            }
            f if f.starts_with("--") => return Err(format!("unknown option {f}\n{TLS_USAGE}")),
            _ if target.is_none() => target = Some(a),
            _ => return Err(TLS_USAGE.into()),
        }
    }
    let raw = target.ok_or(TLS_USAGE)?;
    let (host, port) = split_port(&raw);
    let t = parse_target(host)?;
    if !matches!(t.kind, Kind::Domain | Kind::Hostname | Kind::Ip) {
        return Err(format!("tls needs a domain, host name or IP, not {:?}", t.kind));
    }
    let port = port.unwrap_or(443);
    let r = check_tls(&t.value, port, timeout).await.map_err(|e| e.to_string())?;
    let mut findings = tls_findings(&t.value, port, &r);
    findings.extend(ocsp_findings(&t.value, port, &r));
    if json {
        let out = serde_json::json!({ "result": r, "findings": findings });
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        return Ok(());
    }
    println!("{}:{port}  {}  {}", t.value, r.version, r.cipher);
    let trust = match r.trust {
        Trust::Ok => "chains to a trusted root",
        Trust::SelfSigned => "self-signed",
        Trust::MissingIntermediate => "intermediate missing",
        Trust::UnknownAuthority => "unknown authority",
        Trust::Invalid => "does not verify",
    };
    println!("  OCSP stapling: {}", if r.ocsp_stapled { "yes" } else { "no" });
    println!(
        "  trust: {trust}; name {}; verified: {}",
        if r.hostname_match { "matches" } else { "does NOT match" },
        if r.verified { "yes" } else { "NO" }
    );
    for (i, c) in r.chain.iter().enumerate() {
        println!("  [{i}] {} (issuer {})", c.subject, c.issuer);
        println!(
            "      {}{}, signature {}, valid {} to {}",
            c.key,
            if c.self_signed { " (self-signed)" } else { "" },
            c.signature,
            c.not_before.date(),
            c.not_after.date()
        );
        if !c.sans.is_empty() {
            println!("      names: {}", c.sans.join(", "));
        }
    }
    println!();
    print_findings(&findings);
    Ok(())
}

async fn ports(mut it: std::vec::IntoIter<String>) -> Result<(), String> {
    let (mut target, mut json, mut full, mut dial) = (None, false, false, Duration::from_secs(2));
    let mut chosen: Vec<ServicePort> = vec![];
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--full" => full = true,
            "--timeout-ms" => {
                dial = Duration::from_millis(value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?)
            }
            "--port" => {
                let p: u16 = value("--port")?.parse().map_err(|_| "--port needs a number from 1 to 65535")?;
                if p == 0 || chosen.len() >= 64 {
                    return Err("--port needs a number from 1 to 65535, at most 64 times".into());
                }
                chosen.push(service_for(p));
            }
            f if f.starts_with("--") => return Err(format!("unknown option {f}\n{PORTS_USAGE}")),
            _ if target.is_none() => target = Some(a),
            _ => return Err(PORTS_USAGE.into()),
        }
    }
    let t = parse_target(&target.ok_or(PORTS_USAGE)?)?;
    if !matches!(t.kind, Kind::Domain | Kind::Hostname | Kind::Ip) {
        return Err(format!("ports needs a domain, host name or IP, not {:?}", t.kind));
    }
    let table: &[ServicePort] = if !chosen.is_empty() {
        &chosen
    } else if full {
        FULL
    } else {
        QUICK
    };
    let addresses = resolve_target(&t.value, dial.max(Duration::from_secs(4))).await.map_err(|e| e.to_string())?;
    let r = probe(&addresses, table, Timing { dial, ..Timing::default() }).await;
    let findings = ports_findings(&t.value, &r);
    if json {
        let out = serde_json::json!({ "result": r, "findings": findings });
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        return Ok(());
    }
    println!("{} ({:?}): {} addresses, {} ports", t.value, t.kind, r.addresses.len(), table.len());
    if t.kind != Kind::Ip && !has_ipv6().await {
        println!("  (this machine has no IPv6 route, so IPv6 addresses are not tested)");
    }
    for p in &r.ports {
        let state = match p.state {
            PortState::Open => "open",
            PortState::Closed => "closed (refused)",
            PortState::Filtered => "filtered (no answer)",
            PortState::NoRoute => "no route from this network",
        };
        println!(
            "  {:<40} {:>5}  {:<22} {state}{}",
            p.address.to_string(),
            p.port,
            p.service,
            p.banner.as_deref().map(|b| format!("  {b}")).unwrap_or_default()
        );
    }
    println!();
    print_findings(&findings);
    Ok(())
}

const SMTP_USAGE: &str = "usage: zombo smtp <host[:port]> [--implicit-tls | --starttls] [--ehlo NAME] [--resolver ip[:port]]... [--timeout-ms N] [--json]";
const CAA_USAGE: &str =
    "usage: zombo caa <domain|host> [--port N] [--no-cert] [--resolver ip[:port]]... [--timeout-ms N] [--json]";

async fn smtp(mut it: std::vec::IntoIter<String>) -> Result<(), String> {
    let (mut target, mut json, mut timeout, mut resolvers, mut mode, mut ehlo) =
        (None, false, Duration::from_secs(10), vec![], None, None);
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--implicit-tls" => mode = Some(Mode::Implicit),
            "--starttls" => mode = Some(Mode::Starttls),
            "--ehlo" => ehlo = Some(value("--ehlo")?),
            "--timeout-ms" => {
                timeout =
                    Duration::from_millis(value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?)
            }
            "--resolver" => resolvers.push(addr(&value("--resolver")?)?),
            f if f.starts_with("--") => return Err(format!("unknown option {f}\n{SMTP_USAGE}")),
            _ if target.is_none() => target = Some(a),
            _ => return Err(SMTP_USAGE.into()),
        }
    }
    let raw = target.ok_or(SMTP_USAGE)?;
    let (host, port) = split_port(&raw);
    let t = parse_target(host)?;
    if !matches!(t.kind, Kind::Domain | Kind::Hostname | Kind::Ip) {
        return Err(format!("smtp needs a mail host name or IP, not {:?}", t.kind));
    }
    let port = port.unwrap_or(25);
    let mut o = SmtpOptions::for_port(port);
    o.mode = mode.unwrap_or(o.mode);
    if let Some(name) = ehlo {
        if !valid_ehlo_name(&name) {
            return Err(format!("{name:?} is not usable as an EHLO name"));
        }
        o.ehlo_name = name;
    }
    o.timing.connect = timeout;
    o.timing.step = timeout;
    o.timing.overall = timeout * 3;
    let r = check_smtp(&t.value, port, &o).await;

    let mut expect = vec![];
    if t.kind != Kind::Ip {
        expect.push(t.value.clone());
    }
    if let (Some(ip), true) = (r.peer, r.reach == Reach::Answered) {
        if resolvers.is_empty() {
            resolvers = system_resolvers();
        }
        if !resolvers.is_empty()
            && let RdnsResult::Ip { ptrs, .. } = check_rdns(&resolvers, &ip.to_string(), Duration::from_secs(3)).await
        {
            expect.extend(ptrs.into_iter().map(|p| p.name));
        }
    }
    let findings = smtp_findings(&r, &expect);
    if json {
        let out = serde_json::json!({ "result": r, "findings": findings });
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        return Ok(());
    }
    let peer = r.peer.map(|p| format!(" ({p})")).unwrap_or_default();
    println!("{}:{}{peer}  {}", r.host, r.port, if r.mode == Mode::Implicit { "implicit TLS" } else { "STARTTLS" });
    if let Some(b) = &r.banner {
        println!("  banner: {} {}", b.code, b.text);
    }
    let show = |label: &str, e: &zombo_core::smtp::Extensions| {
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
        println!("  {label}: {}", parts.join(", "));
    };
    if let Some(e) = &r.extensions {
        show(if r.mode == Mode::Implicit { "offers" } else { "offers before TLS" }, e);
    }
    match &r.starttls {
        Starttls::Upgraded => println!("  STARTTLS: accepted"),
        Starttls::Refused { code, text } => println!("  STARTTLS: refused ({code} {text})"),
        Starttls::HandshakeFailed(why) => println!("  STARTTLS: handshake failed ({why})"),
        Starttls::NotOffered => println!("  STARTTLS: not offered"),
        Starttls::NotApplicable | Starttls::NotAttempted => {}
    }
    if let Some(e) = &r.extensions_after_tls {
        show("offers after TLS", e);
    }
    if let Some(c) = &r.tls {
        println!(
            "  TLS: {} {}; name {}; verified: {}",
            c.version,
            c.cipher,
            if c.hostname_match { "matches" } else { "does NOT match" },
            if c.verified { "yes" } else { "NO" }
        );
        for (i, cert) in c.chain.iter().enumerate() {
            println!(
                "  [{i}] {} (issuer {}) valid {} to {}",
                cert.subject,
                cert.issuer,
                cert.not_before.date(),
                cert.not_after.date()
            );
        }
    }
    println!();
    print_findings(&findings);
    Ok(())
}

async fn caa(mut it: std::vec::IntoIter<String>) -> Result<(), String> {
    let (mut target, mut json, mut timeout, mut resolvers, mut port, mut cert) =
        (None, false, Duration::from_secs(4), vec![], 443u16, true);
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--no-cert" => cert = false,
            "--port" => port = value("--port")?.parse().map_err(|_| "--port needs a number")?,
            "--timeout-ms" => {
                timeout =
                    Duration::from_millis(value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?)
            }
            "--resolver" => resolvers.push(addr(&value("--resolver")?)?),
            f if f.starts_with("--") => return Err(format!("unknown option {f}\n{CAA_USAGE}")),
            _ if target.is_none() => target = Some(a),
            _ => return Err(CAA_USAGE.into()),
        }
    }
    let t = parse_target(&target.ok_or(CAA_USAGE)?)?;
    if !matches!(t.kind, Kind::Domain | Kind::Hostname) {
        return Err(format!("caa needs a domain or host name, not {:?}", t.kind));
    }
    if resolvers.is_empty() {
        resolvers = system_resolvers();
    }
    if resolvers.is_empty() {
        return Err("no DNS resolver found in /etc/resolv.conf; pass --resolver ip[:port]".into());
    }
    let r = check_caa(&resolvers, &t.value, timeout).await;
    let (served, cert_error) = if cert {
        match check_tls(&t.value, port, timeout * 2).await {
            Ok(c) => (Some(c), None),
            Err(e) => (None, Some(e.to_string())),
        }
    } else {
        (None, None)
    };
    let findings = caa_findings(&r, served.as_ref());
    if json {
        let out = serde_json::json!({ "result": r, "certificate_error": cert_error, "findings": findings });
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        return Ok(());
    }
    println!("{} via {}", t.value, join(&resolvers));
    match &r.found_at {
        Some(at) => println!("  CAA records on {at}:"),
        None => println!("  no CAA records"),
    }
    for c in &r.records {
        println!("    {}{} \"{}\"", if c.critical { "critical " } else { "" }, c.tag, c.value);
    }
    if let Some(c) = &served {
        println!(
            "  served certificate on port {port}: issued by {}",
            c.chain.first().map_or("?", |l| l.issuer.as_str())
        );
    }
    if let Some(e) = cert_error {
        println!("  could not read the certificate on port {port} ({e}); the issuer was not compared");
    }
    println!();
    print_findings(&findings);
    Ok(())
}

const CHECKS_USAGE: &str = "usage: zombo checks [--json]";

fn kind_name(k: Kind) -> String {
    format!("{k:?}").to_lowercase()
}

fn checks(it: std::vec::IntoIter<String>) -> Result<(), String> {
    let mut json = false;
    for a in it {
        match a.as_str() {
            "--json" => json = true,
            _ => return Err(CHECKS_USAGE.into()),
        }
    }
    let kinds = |c: &zombo_core::check::Check| c.accepts.iter().map(|k| kind_name(*k)).collect::<Vec<_>>();
    if json {
        let rows: Vec<_> = zombo_core::check::ALL
            .iter()
            .map(|c| {
                serde_json::json!({
                    "id": c.id,
                    "label": c.label,
                    "accepts": kinds(c),
                    "automatic": !c.is_on_demand(),
                    "query_secs": c.budget.1.as_secs_f64(),
                    "whole_secs": c.budget.0.as_secs_f64(),
                })
            })
            .collect();
        return print_json(&serde_json::Value::Array(rows));
    }
    for c in zombo_core::check::ALL {
        let when = if c.is_on_demand() { "on demand" } else { "automatic" };
        println!(
            "{:<13} {:<20} {:<28} {:<10} {}s per query, {}s whole",
            c.id,
            c.label,
            kinds(c).join(","),
            when,
            c.budget.1.as_secs_f64(),
            c.budget.0.as_secs_f64()
        );
    }
    Ok(())
}

const RUN_USAGE: &str = "usage: zombo run <id> <target> [--timeout-ms N] [--resolver ip[:port]]... [--port N] [--selector NAME]... [--json]";

async fn run_check(mut it: std::vec::IntoIter<String>) -> Result<(), String> {
    let (mut positional, mut json, mut timeout, mut resolvers, mut port) = (vec![], false, None, vec![], None);
    let mut selectors = vec![];
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--timeout-ms" => {
                let ms = value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?;
                timeout = Some(Duration::from_millis(ms));
            }
            "--resolver" => resolvers.push(addr(&value("--resolver")?)?),
            "--port" => {
                port = Some(value("--port")?.parse::<u16>().map_err(|_| "--port needs a number from 1 to 65535")?);
            }
            "--selector" => selectors.push(value("--selector")?),
            f if f.starts_with("--") => return Err(format!("unknown option {f}\n{RUN_USAGE}")),
            _ => positional.push(a),
        }
    }
    let [id, target] = &positional[..] else { return Err(RUN_USAGE.into()) };
    let args = zombo_core::check::RunArgs {
        timeout,
        resolvers: &resolvers,
        port,
        selectors: &selectors,
        ..zombo_core::check::RunArgs::new(target)
    };
    let report = zombo_core::check::run_by_id(id, &args).await.map_err(|e| e.to_string())?;
    if json {
        let mut v = serde_json::to_value(&report.outcome).map_err(|e| e.to_string())?;
        if let Some(o) = v.as_object_mut() {
            o.insert("check".into(), report.id.into());
            o.insert("target".into(), report.subject.clone().into());
        }
        return print_json(&v);
    }
    println!("{}", report.to_text());
    Ok(())
}
