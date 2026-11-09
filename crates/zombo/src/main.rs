//! `zombo`: the command-line front end to zombo-core.

use std::{net::SocketAddr, process::ExitCode, time::Duration};

use zombo_core::{
    Finding, Severity,
    delegation::{Ports, ServerState, check_delegation, delegation_findings},
    propagation::{Scope, Vantage, VantageAnswer, VantageKind, default_resolvers, discover_nameservers, propagation_findings, propagation_with},
    target::{Kind, parse_target},
};
use zombo_core::email_auth::{Alignment, EffectiveAll, KeyType, email_auth, email_findings, parse_selectors};

const USAGE: &str = "usage: zombo delegation <domain|host> [--resolver ip[:port]]... [--timeout-ms N] [--json]\n       zombo propagation <domain|host> [--scope all|mail|web] [--resolver ip[:port]]... [--nameserver ip[:port]]... [--no-authoritative] [--timeout-ms N] [--json]";

fn addr(v: &str) -> Result<SocketAddr, String> {
    v.parse()
        .or_else(|_| format!("{v}:53").parse())
        .or_else(|_| format!("[{v}]:53").parse())
        .map_err(|_| format!("{v:?} is not an IP address"))
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
        Some("propagation") => propagation(it).await,
        Some("delegation") => delegation(it).await,
        Some("email") => email(it).await,
        _ => Err(USAGE.into()),
    }
}

const EMAIL_USAGE: &str = "usage: zombo email <domain|host> [--selector NAME]... [--resolver ip[:port]] [--timeout-ms N] [--json]";

async fn email(mut it: std::vec::IntoIter<String>) -> Result<(), String> {
    let (mut target, mut json, mut timeout, mut resolver) = (None, false, Duration::from_secs(4), None);
    let mut selectors = vec![];
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--timeout-ms" => {
                timeout = Duration::from_millis(value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?)
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
    let resolver = resolver.unwrap_or_else(|| default_resolvers()[0].address);
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
    let dkim = if keys.is_empty() { format!("none found among {} selectors", r.dkim.checked.len()) } else { keys.join(", ") };
    println!("  {:<8} {dkim}", "DKIM");
    let d = &r.dmarc;
    let dmarc = match &d.parsed {
        Some(p) => {
            let sp = p.subdomain_policy.map_or(String::new(), |sp| format!("; sp={sp}"));
            let policy = p.policy.map_or("no valid policy".to_string(), |p| format!("p={p}"));
            let strict = |a: Alignment| if a == Alignment::Strict { "s" } else { "r" };
            format!("{policy}{sp}; pct={}; adkim={}; aspf={}; rua={}", p.pct, strict(p.adkim), strict(p.aspf), list(&p.rua))
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
        if let Some(r) = f.recommendation {
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
                timeout = Duration::from_millis(value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?)
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

async fn propagation(mut it: std::vec::IntoIter<String>) -> Result<(), String> {
    let (mut target, mut scope, mut json, mut timeout) = (None, Scope::All, false, Duration::from_secs(4));
    let (mut resolvers, mut nameservers, mut no_auth) = (vec![], vec![], false);
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--scope" => scope = value("--scope")?.parse()?,
            "--timeout-ms" => {
                timeout = Duration::from_millis(value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?)
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
                rcode.unwrap(),
                a.answers.len(),
                if a.authoritative == Some(false) && r.kind == VantageKind::Authoritative { "  (NOT authoritative)" } else { "" }
            ),
        }
    };
    if !json {
        println!("{} ({:?}): {} resolvers, {} authoritative nameservers", t.value, t.kind, resolvers.len(), nameservers.len());
    }
    let res = propagation_with(&resolvers, &nameservers, &t.value, scope, timeout, show).await.map_err(|e| e.to_string())?;
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
